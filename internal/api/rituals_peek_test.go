package api

// Rituals fork: peek, claim seat hints, the fresh marks SQL and the limiter
// exemption. The unit tests need no database; TestRitualsSeatsAndMarksDB runs
// against TEST_DATABASE_URL (skipped when unset) with synthetic users and
// keys generated per run.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hushhq/hush-server/internal/db"
	"github.com/hushhq/hush-server/internal/livekit"
)

func ritualsTestHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func ritualsTestTicket(t *testing.T, priv ed25519.PrivateKey, now time.Time, sp, sub, role string) *ritualsTicket {
	t.Helper()
	return &ritualsTicket{V: 1, Aud: "https://space.rit.al", Sp: sp, Sub: sub, Role: role, Name: "Synthetic task",
		Dn: "Synthetic", Iat: now.Unix(), Exp: now.Unix() + 600, Jti: ritualsTestHex(t, 16)}
}

func TestRitualsExemptServerToServer(t *testing.T) {
	limited := 0
	limiter := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limited++
			next.ServeHTTP(w, r)
		})
	}
	h := RitualsExemptServerToServer(limiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cases := []struct {
		method, path string
		limited      bool
	}{
		{http.MethodPost, "/api/rituals/spaces/sync", false},
		{http.MethodPost, "/api/rituals/spaces/fresh", false},
		{http.MethodGet, "/api/rituals/spaces/fresh", true},
		{http.MethodPost, "/api/rituals/spaces/peek", true},
		{http.MethodPost, "/api/rituals/spaces/claim", true},
		{http.MethodPost, "/api/rituals/spaces/sync/", true},
		{http.MethodPost, "/api/auth/login", true},
	}
	for _, c := range cases {
		before := limited
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(c.method, c.path, nil))
		if got := limited > before; got != c.limited {
			t.Errorf("%s %s: limited=%v, want %v", c.method, c.path, got, c.limited)
		}
	}
}

func TestRitualsPeekRejectsBadTickets(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	rt := &ritualsRuntime{origin: "https://space.rit.al", pubKey: pub, now: func() time.Time { return now }}
	sp := strings.Repeat("ab", 32)
	expired := ritualsTestTicket(t, priv, now.Add(-2*time.Hour), sp, sp, "member")
	expired.Exp = now.Unix() - 3600
	cases := map[string]struct {
		body   string
		status int
		code   string
	}{
		"not json":     {`{`, http.StatusBadRequest, "bad_ticket"},
		"wrong prefix": {`{"ticket":"rts1.x.y"}`, http.StatusBadRequest, "bad_ticket"},
		"expired": {`{"ticket":"` + ritualsTestSign(t, priv, ritualsTicketPrefix, ritualsTicketDomain, expired) + `"}`,
			http.StatusForbidden, "ticket_expired"},
		"fresh domain": {`{"ticket":"` + ritualsTestSign(t, priv, ritualsTicketPrefix, ritualsFreshDomain,
			ritualsTestTicket(t, priv, now, sp, sp, "member")) + `"}`, http.StatusBadRequest, "bad_ticket"},
	}
	for name, c := range cases {
		w := httptest.NewRecorder()
		rt.handlePeek(w, httptest.NewRequest(http.MethodPost, "/spaces/peek", strings.NewReader(c.body)))
		if w.Code != c.status || !strings.Contains(w.Body.String(), `"`+c.code+`"`) {
			t.Errorf("%s: %d %s, want %d %s", name, w.Code, w.Body.String(), c.status, c.code)
		}
	}
}

func TestRitualsSeatsAndMarksDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	if err := RitualsBootstrap(ctx, pool); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rt := &ritualsRuntime{origin: "https://space.rit.al", pubKey: pub, pool: pool,
		roomService: livekit.NoopRoomService{}, now: func() time.Time { return now }}
	user := func() string {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		u, err := pool.CreateUserWithPublicKey(ctx, "rt"+ritualsTestHex(t, 6), "Synthetic", key)
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	sp, subA, subB, subC := ritualsTestHex(t, 32), ritualsTestHex(t, 32), ritualsTestHex(t, 32), ritualsTestHex(t, 32)
	unknown := ritualsTestHex(t, 32)
	alice, bob, aliceTwo := user(), user(), user()

	peek := func(sub string, want ritualsPeekResult) {
		t.Helper()
		res, perr, err := rt.peekSpace(ctx, ritualsTestTicket(t, priv, now, sp, sub, "member"))
		if err != nil || perr != nil || *res != want {
			t.Fatalf("peek %s: %+v %v %v, want %+v", sub[:6], res, perr, err, want)
		}
	}
	claim := func(userID, sub, role string, self, others bool) {
		t.Helper()
		res, cerr, err := rt.claimSpace(ctx, userID, ritualsTestTicket(t, priv, now, sp, sub, role))
		if err != nil || cerr != nil {
			t.Fatalf("claim: %v %v", cerr, err)
		}
		if res.selfSeated != self || res.othersSeated != others {
			t.Fatalf("claim %s: self=%v others=%v, want %v %v", sub[:6], res.selfSeated, res.othersSeated, self, others)
		}
	}

	peek(subA, ritualsPeekResult{})
	claim(alice, subA, "owner", false, false)
	peek(subA, ritualsPeekResult{Claimed: true, SelfSeated: true})
	peek(subB, ritualsPeekResult{Claimed: true, OthersSeated: true})
	if res, _, _ := rt.peekSpace(ctx, ritualsTestTicket(t, priv, now, unknown, subA, "member")); *res != (ritualsPeekResult{}) {
		t.Fatalf("unknown space: %+v", res)
	}
	claim(bob, subB, "member", false, true)
	claim(aliceTwo, subA, "member", true, true) // Alice's second device
	peek(subA, ritualsPeekResult{Claimed: true, SelfSeated: true, OthersSeated: true})
	// A peek never consumes the jti or writes anything.
	var tickets int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM rituals.registration_tickets`).Scan(&tickets); err != nil {
		t.Fatal(err)
	}

	// Marks: the newest text message not sent by this sub's seats.
	var serverID, channelID string
	if err := pool.QueryRow(ctx, `SELECT s.server_id, c.id FROM rituals.spaces s JOIN channels c
		ON c.server_id = s.server_id AND c.type = 'text' WHERE s.sp = $1`, sp).Scan(&serverID, &channelID); err != nil {
		t.Fatal(err)
	}
	send := func(from string, to *string, at time.Time) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO messages (channel_id, sender_id, recipient_id, ciphertext, "timestamp")
			VALUES ($1, $2, $3, '\x00', $4) RETURNING id::text`, channelID, from, to, at).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	marks := func(want ...string) {
		t.Helper()
		pairs := []ritualsFreshPair{{Sp: sp, Sub: subA}, {Sp: sp, Sub: subB}, {Sp: sp, Sub: subC}, {Sp: unknown, Sub: subA}}
		got, err := rt.queryMarks(httptest.NewRequest(http.MethodPost, "/", nil), pairs)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("marks = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("marks = %v, want %v", got, want)
			}
		}
	}
	m := ritualsMark
	marks("", "", "", "") // no messages; subC never claimed; unknown sp
	fromBob := send(bob, nil, now.Add(-3*time.Minute))
	marks(m(fromBob), "", "", "")
	// Alice's own newer message (second device) does not move her mark: her
	// pair falls back to Bob's row; Bob's pair now sees Alice's.
	fromAlice := send(aliceTwo, nil, now.Add(-2*time.Minute))
	marks(m(fromBob), m(fromAlice), "", "")
	// A row addressed to Bob only counts for Bob, never for Alice.
	toBob := send(alice, &bob, now.Add(-time.Minute))
	marks(m(fromBob), m(toBob), "", "")
	// Same timestamp: the larger id wins, deterministically.
	tie := now.Add(-30 * time.Second)
	x, y := send(bob, nil, tie), send(bob, nil, tie)
	if y < x {
		x, y = y, x
	}
	marks(m(y), m(toBob), "", "")
	_ = x

	// Revocation: a sync newer than the ticket that drops Bob makes his peek a 403.
	if _, err := pool.Exec(ctx, `UPDATE rituals.spaces SET last_sync_iat = $2, allowed_subs = ARRAY[$3]::text[] WHERE sp = $1`,
		sp, now.Unix()+5, subA); err != nil {
		t.Fatal(err)
	}
	if _, perr, err := rt.peekSpace(ctx, ritualsTestTicket(t, priv, now, sp, subB, "member")); err != nil || perr == nil || perr.code != "ticket_revoked" {
		t.Fatalf("revoked peek: %v %v", perr, err)
	}
	peek(subA, ritualsPeekResult{Claimed: true, SelfSeated: true, OthersSeated: true})
	var after int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM rituals.registration_tickets`).Scan(&after); err != nil || after != tickets {
		t.Fatalf("peek wrote registration tickets: %d -> %d (%v)", tickets, after, err)
	}
	_ = serverID
}
