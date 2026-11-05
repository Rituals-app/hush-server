package api

// Rituals fork: text-commit CAS (wire contract Item 1) and pending MLS
// removals (Item 2). Unit tests use synthetic framing bytes; the DB tests run
// against TEST_DATABASE_URL (skipped when unset) with synthetic users, keys
// and device ids generated per run.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hushhq/hush-server/internal/db"
	"github.com/hushhq/hush-server/internal/livekit"
	"github.com/hushhq/hush-server/internal/version"
)

// ritualsTestCommit is a synthetic MLSMessage prefix: version 1, the given
// wire format, a group id of gidLen bytes with a varint of varintSize bytes,
// the epoch, then filler standing in for the rest of the message.
func ritualsTestCommit(wireFormat uint16, gidLen, varintSize int, epoch uint64) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(1))
	_ = binary.Write(&b, binary.BigEndian, wireFormat)
	switch varintSize {
	case 1:
		b.WriteByte(byte(gidLen))
	case 2:
		_ = binary.Write(&b, binary.BigEndian, uint16(gidLen)|0x4000)
	case 4:
		_ = binary.Write(&b, binary.BigEndian, uint32(gidLen)|0x80000000)
	}
	b.Write(bytes.Repeat([]byte{0x4a}, gidLen))
	_ = binary.Write(&b, binary.BigEndian, epoch)
	b.Write([]byte("synthetic-commit-body"))
	return b.Bytes()
}

func TestRitualsCommitEpoch(t *testing.T) {
	cases := []struct {
		name  string
		in    []byte
		epoch int64
		ok    bool
	}{
		{"public, 16-byte id", ritualsTestCommit(1, 16, 1, 7), 7, true},
		{"private, 2-byte varint", ritualsTestCommit(2, 100, 2, 1<<40), 1 << 40, true},
		{"4-byte varint", ritualsTestCommit(1, 3, 4, 0), 0, true},
		{"empty id", ritualsTestCommit(1, 0, 1, 12), 12, true},
		{"wrong version", append([]byte{0, 2}, ritualsTestCommit(1, 16, 1, 7)[2:]...), 0, false},
		{"welcome wire format", append([]byte{0, 1, 0, 3}, ritualsTestCommit(1, 16, 1, 7)[4:]...), 0, false},
		{"varint prefix 11", []byte{0, 1, 0, 1, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, false},
		{"truncated epoch", ritualsTestCommit(1, 16, 1, 7)[:4+1+16+7], 0, false},
		{"id longer than input", []byte{0, 1, 0, 1, 0x3f, 1, 2}, 0, false},
		{"epoch above int64", ritualsTestCommit(1, 4, 1, 1<<63), 0, false},
		{"max int64 epoch", ritualsTestCommit(1, 4, 1, 1<<63-1), 0, false},
		{"empty", nil, 0, false},
	}
	for _, c := range cases {
		epoch, ok := ritualsCommitEpoch(c.in)
		if ok != c.ok || (ok && epoch != c.epoch) {
			t.Errorf("%s: %d %v, want %d %v", c.name, epoch, ok, c.epoch, c.ok)
		}
	}
}

func TestRitualsParseRemoves(t *testing.T) {
	u := "3f2b8c1e-9d4a-4c6b-8e21-7a5d0f9b1c34"
	many := make([]string, 65)
	for i := range many {
		many[i] = fmt.Sprintf(`{"userId":%q,"deviceId":"d%d"}`, u, i)
	}
	cases := []struct {
		raw string
		n   int
		ok  bool
	}{
		{``, 0, true},
		{`null`, 0, true},
		{`[]`, 0, true},
		{`[{"userId":"` + u + `","deviceId":"synthetic-device"}]`, 1, true},
		{`[{"userId":"` + strings.ToUpper(u) + `","deviceId":"d"}]`, 1, true},
		{`[{"userId":"not-a-uuid","deviceId":"d"}]`, 0, false},
		{`[{"userId":"` + u + `","deviceId":""}]`, 0, false},
		{`[{"userId":"` + u + `","deviceId":"` + strings.Repeat("x", 129) + `"}]`, 0, false},
		{`{"userId":"` + u + `"}`, 0, false},
		{`[` + strings.Join(many[:64], ",") + `]`, 64, true},
		{`[` + strings.Join(many, ",") + `]`, 0, false},
	}
	for _, c := range cases {
		users, devices, ok := ritualsParseRemoves(json.RawMessage(c.raw))
		if ok != c.ok || len(users) != c.n || len(devices) != c.n {
			t.Errorf("%.40s: %d %v, want %d %v", c.raw, len(users), ok, c.n, c.ok)
		}
		if ok && c.n > 0 && users[0] != u {
			t.Errorf("user id not canonical: %s", users[0])
		}
	}
}

type ritualsFakeMLSHub struct {
	mu     sync.Mutex
	frames []map[string]interface{}
}

func (f *ritualsFakeMLSHub) BroadcastToUser(string, []byte) {}
func (f *ritualsFakeMLSHub) Broadcast(_ string, message []byte, _ string) {
	var m map[string]interface{}
	_ = json.Unmarshal(message, &m)
	f.mu.Lock()
	f.frames = append(f.frames, m)
	f.mu.Unlock()
}

func (f *ritualsFakeMLSHub) take() []map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.frames
	f.frames = nil
	return out
}

// ritualsTestSpace bootstraps the rituals schema and claims one space for
// two synthetic users. It returns the runtime, users, server and text channel.
type ritualsTestSpace struct {
	rt                        *ritualsRuntime
	pool                      *db.Pool
	priv                      ed25519.PrivateKey
	now                       time.Time
	sp, subA, subB            string
	alice, bob                string
	serverID, textCh, voiceCh string
}

func newRitualsTestSpace(t *testing.T, pool *db.Pool) *ritualsTestSpace {
	t.Helper()
	ctx := context.Background()
	if err := RitualsBootstrap(ctx, pool); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &ritualsTestSpace{pool: pool, priv: priv, now: time.Now()}
	s.rt = &ritualsRuntime{origin: "https://space.rit.al", pubKey: pub, pool: pool,
		roomService: livekit.NoopRoomService{}, now: func() time.Time { return s.now }}
	s.sp, s.subA, s.subB = ritualsTestHex(t, 32), ritualsTestHex(t, 32), ritualsTestHex(t, 32)
	s.alice, s.bob = s.user(t), s.user(t)
	s.claim(t, s.alice, s.subA, "owner")
	s.claim(t, s.bob, s.subB, "member")
	if err := pool.QueryRow(ctx, `SELECT s.server_id, c.id FROM rituals.spaces s JOIN channels c
		ON c.server_id = s.server_id AND c.type = 'text' WHERE s.sp = $1`, s.sp).Scan(&s.serverID, &s.textCh); err != nil {
		t.Fatal(err)
	}
	_ = pool.QueryRow(ctx, `SELECT id FROM channels WHERE server_id = $1 AND type = 'voice' LIMIT 1`, s.serverID).Scan(&s.voiceCh)
	return s
}

func (s *ritualsTestSpace) user(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	u, err := s.pool.CreateUserWithPublicKey(context.Background(), "rt"+ritualsTestHex(t, 6), "Synthetic", key)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func (s *ritualsTestSpace) claim(t *testing.T, userID, sub, role string) {
	t.Helper()
	if _, cerr, err := s.rt.claimSpace(context.Background(), userID, ritualsTestTicket(t, s.priv, s.now, s.sp, sub, role)); err != nil || cerr != nil {
		t.Fatalf("claim: %v %v", cerr, err)
	}
}

func (s *ritualsTestSpace) device(t *testing.T, userID, deviceID string) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `INSERT INTO mls_credentials (user_id, device_id, credential_bytes, signing_pub_key)
		VALUES ($1, $2, '\x00', '\x00')`, userID, deviceID); err != nil {
		t.Fatal(err)
	}
}

func ritualsMLSRequest(method, channelID, userID, deviceID, query string, body interface{}) *http.Request {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, "/groups/"+channelID+"/commit"+query, bytes.NewReader(raw))
	rc := chi.NewRouteContext()
	rc.URLParams.Add("channelId", channelID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
	ctx = withDeviceID(withUserID(ctx, userID), deviceID)
	return r.WithContext(ctx)
}

func TestRitualsTextCommitCASDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool)
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)
	hub := &ritualsFakeMLSHub{}
	h := &mlsHandler{store: pool, hub: hub}
	suite := version.CurrentMLSCiphersuite
	b64 := base64.StdEncoding.EncodeToString
	gi := b64([]byte("synthetic-group-info"))

	type body = map[string]interface{}
	post := func(user string, b body) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		h.postCommit(w, ritualsMLSRequest(http.MethodPost, s.textCh, user, "synthetic-device-a", "", b))
		return w
	}
	expect := func(w *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		if w.Code != status || (code != "" && !strings.Contains(w.Body.String(), `"`+code+`"`)) {
			t.Fatalf("got %d %s, want %d %s", w.Code, w.Body.String(), status, code)
		}
	}
	head := func() (int64, int64, int) {
		t.Helper()
		var info, commits int64
		var n int
		if err := pool.QueryRow(ctx, `SELECT
			COALESCE((SELECT epoch FROM mls_group_info WHERE channel_id = $1 AND group_type = 'text'), -1),
			COALESCE((SELECT MAX(epoch) FROM mls_commits WHERE channel_id = $1), -1),
			(SELECT COUNT(*) FROM mls_commits WHERE channel_id = $1)`, s.textCh).Scan(&info, &commits, &n); err != nil {
			t.Fatal(err)
		}
		return info, commits, n
	}

	// A new client's commit built on epoch 0: stored at label 1, broadcast at 1.
	c0 := b64(ritualsTestCommit(2, 16, 1, 0))
	expect(post(s.alice, body{"commitBytes": c0, "groupInfo": gi, "epoch": 1, "parentEpoch": 0, "ciphersuite": suite}), 204, "")
	if info, commits, n := head(); info != 1 || commits != 1 || n != 1 {
		t.Fatalf("after first commit: info=%d commits=%d n=%d", info, commits, n)
	}
	frames := hub.take()
	if len(frames) != 1 || frames[0]["epoch"] != float64(1) || frames[0]["group_type"] != "text" ||
		frames[0]["sender_id"] != s.alice || frames[0]["commit_bytes"] != c0 || frames[0]["type"] != "mls.commit" {
		t.Fatalf("broadcast = %v", frames)
	}

	// A racing commit built on the same epoch loses: 409 with the head, nothing stored or broadcast.
	w := post(s.bob, body{"commitBytes": b64(ritualsTestCommit(2, 16, 1, 0)), "groupInfo": gi, "epoch": 1, "parentEpoch": 0, "ciphersuite": suite})
	expect(w, 409, "epoch_conflict")
	var conflict struct {
		Error        string `json:"error"`
		CurrentEpoch int64  `json:"currentEpoch"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil || conflict.CurrentEpoch != 1 {
		t.Fatalf("409 body %s", w.Body.String())
	}
	if _, _, n := head(); n != 1 || len(hub.take()) != 0 {
		t.Fatalf("loser stored or broadcast")
	}
	// An old client's member commit (no parentEpoch, pre-merge epoch label)
	// built on a stale epoch also gets 409, with no new fields required.
	expect(post(s.bob, body{"commitBytes": b64(ritualsTestCommit(1, 16, 1, 0)), "epoch": 0, "ciphersuite": suite}), 409, "epoch_conflict")

	// Validation, in order.
	expect(post(s.bob, body{"commitBytes": b64(ritualsTestCommit(2, 16, 1, 1)), "groupInfo": gi, "epoch": 2, "parentEpoch": 5, "ciphersuite": suite}), 400, "parent_epoch_mismatch")
	expect(post(s.bob, body{"commitBytes": b64(ritualsTestCommit(2, 16, 1, 1)), "epoch": 2, "parentEpoch": 1, "ciphersuite": suite}), 400, "group_info_required")
	expect(post(s.bob, body{"commitBytes": b64(ritualsTestCommit(2, 16, 1, 1)), "groupInfo": gi, "epoch": 3, "parentEpoch": 1, "ciphersuite": suite}), 400, "bad_epoch")
	expect(post(s.bob, body{"commitBytes": b64([]byte("opaque")), "groupInfo": gi, "epoch": 3, "parentEpoch": -1, "ciphersuite": suite}), 400, "bad_epoch")
	expect(post(s.bob, body{"commitBytes": b64(ritualsTestCommit(2, 16, 1, 1)), "groupInfo": gi, "epoch": 2, "parentEpoch": 1, "ciphersuite": suite,
		"removes": []body{{"userId": "nope", "deviceId": "d"}}}), 400, "bad_removes")
	if _, _, n := head(); n != 1 || len(hub.take()) != 0 {
		t.Fatalf("a rejected commit was stored or broadcast")
	}

	// An old client's member commit built on the head (epoch == builtOn) is
	// relabelled builtOn+1 by the server (no groupInfo: the info row stays).
	expect(post(s.bob, body{"commitBytes": b64(ritualsTestCommit(1, 16, 1, 1)), "epoch": 1, "ciphersuite": suite}), 204, "")
	if info, commits, _ := head(); info != 1 || commits != 2 {
		t.Fatalf("old member commit: info=%d commits=%d, want 1 2", info, commits)
	}
	if f := hub.take(); len(f) != 1 || f[0]["epoch"] != float64(2) {
		t.Fatalf("old member commit broadcast %v", f)
	}

	// Unparseable framing with parentEpoch: builtOn = parentEpoch.
	expect(post(s.alice, body{"commitBytes": b64([]byte("opaque")), "groupInfo": gi, "epoch": 3, "parentEpoch": 2, "ciphersuite": suite}), 204, "")
	// builtOn ahead of the head (lagging G1 history) is accepted.
	expect(post(s.alice, body{"commitBytes": b64(ritualsTestCommit(1, 16, 1, 9)), "groupInfo": gi, "epoch": 10, "parentEpoch": 9, "ciphersuite": suite}), 204, "")
	if info, commits, n := head(); info != 10 || commits != 10 || n != 4 {
		t.Fatalf("after ahead commit: info=%d commits=%d n=%d", info, commits, n)
	}
	hub.take()

	// Legacy path: unparseable framing, no parentEpoch: stored exactly as
	// upstream does, at the client's epoch, with no CAS.
	expect(post(s.bob, body{"commitBytes": b64([]byte("opaque")), "epoch": 4, "ciphersuite": suite}), 204, "")
	if _, _, n := head(); n != 5 {
		t.Fatalf("legacy commit not stored: n=%d", n)
	}
	if f := hub.take(); len(f) != 1 || f[0]["epoch"] != float64(4) {
		t.Fatalf("legacy broadcast %v", f)
	}

	// PUT text group info is monotonic and always 204.
	put := func(epoch int64) {
		t.Helper()
		w := httptest.NewRecorder()
		h.putGroupInfo(w, ritualsMLSRequest(http.MethodPut, s.textCh, s.alice, "synthetic-device-a", "",
			body{"groupInfo": b64([]byte(fmt.Sprintf("synthetic-info-%d", epoch))), "epoch": epoch, "ciphersuite": suite}))
		expect(w, 204, "")
	}
	put(3)
	if info, _, _ := head(); info != 10 {
		t.Fatalf("older PUT overwrote group info: %d", info)
	}
	put(10)
	put(11)
	if info, _, _ := head(); info != 11 {
		t.Fatalf("newer PUT skipped: %d", info)
	}

	// A commit's removes hint clears the matching pending records only.
	carol := s.user(t)
	if _, err := pool.Exec(ctx, `INSERT INTO rituals.pending_mls_removals (channel_id, user_id, device_id)
		VALUES ($1, $2, 'synthetic-dev-1'), ($1, $2, 'synthetic-dev-2')`, s.textCh, carol); err != nil {
		t.Fatal(err)
	}
	expect(post(s.alice, body{"commitBytes": b64(ritualsTestCommit(2, 16, 1, 11)), "groupInfo": gi, "epoch": 12, "parentEpoch": 11, "ciphersuite": suite,
		"removes": []body{{"userId": carol, "deviceId": "synthetic-dev-1"}}}), 204, "")
	var left []string
	rows, err := pool.Query(ctx, `SELECT device_id FROM rituals.pending_mls_removals WHERE channel_id = $1`, s.textCh)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var d string
		_ = rows.Scan(&d)
		left = append(left, d)
	}
	rows.Close()
	if len(left) != 1 || left[0] != "synthetic-dev-2" {
		t.Fatalf("pending after hint: %v", left)
	}
	hub.take()

	// Concurrent racers on the same builtOn: exactly one 204, the rest 409.
	const racers = 8
	var wg sync.WaitGroup
	codes := make([]int, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			user := s.alice
			if i%2 == 1 {
				user = s.bob
			}
			h.postCommit(w, ritualsMLSRequest(http.MethodPost, s.textCh, user, "synthetic-device-a", "",
				body{"commitBytes": b64(ritualsTestCommit(2, 16, 1, 12)), "groupInfo": gi, "epoch": 13, "parentEpoch": 12, "ciphersuite": suite}))
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()
	won := 0
	for _, c := range codes {
		switch c {
		case 204:
			won++
		case 409:
		default:
			t.Fatalf("racer code %d", c)
		}
	}
	if won != 1 {
		t.Fatalf("racers: %d winners (%v)", won, codes)
	}
	var at13 int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM mls_commits WHERE channel_id = $1 AND epoch = 13`, s.textCh).Scan(&at13); err != nil || at13 != 1 {
		t.Fatalf("rows at epoch 13: %d %v", at13, err)
	}

	// Voice keeps the upstream blind path.
	if s.voiceCh != "" {
		w := httptest.NewRecorder()
		h.postCommit(w, ritualsMLSRequest(http.MethodPost, s.voiceCh, s.alice, "synthetic-device-a", "?type=voice",
			body{"commitBytes": b64(ritualsTestCommit(1, 16, 1, 0)), "epoch": 0, "ciphersuite": suite}))
		h.postCommit(httptest.NewRecorder(), ritualsMLSRequest(http.MethodPost, s.voiceCh, s.bob, "synthetic-device-a", "?type=voice",
			body{"commitBytes": b64(ritualsTestCommit(1, 16, 1, 0)), "epoch": 0, "ciphersuite": suite}))
		var n int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM mls_commits WHERE channel_id = $1 AND epoch = 0`, s.voiceCh).Scan(&n); err != nil || w.Code != 204 || n != 2 {
			t.Fatalf("voice path: %d rows, code %d, %v", n, w.Code, err)
		}
	}
}

func TestRitualsPendingRemovalsDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool)
	s.device(t, s.bob, "synthetic-bob-1")
	s.device(t, s.bob, "synthetic-bob-2")
	s.device(t, s.alice, "synthetic-alice-1")

	// A second text channel in the same space.
	var text2 string
	if err := pool.QueryRow(ctx, `INSERT INTO channels (server_id, encrypted_metadata, type, position)
		VALUES ($1, '\x00', 'text', 9) RETURNING id`, s.serverID).Scan(&text2); err != nil {
		t.Fatal(err)
	}

	// Sync without Bob: one record per text channel x Bob's device.
	s.now = s.now.Add(time.Second)
	res, err := s.rt.applySync(ctx, &ritualsSync{V: 1, Aud: "https://space.rit.al", Sp: s.sp, Subs: []string{s.subA},
		Iat: s.now.Unix(), Exp: s.now.Unix() + 600})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.removedMembers) != 1 || res.removedMembers[0] != s.bob {
		t.Fatalf("removed = %v", res.removedMembers)
	}
	count := func(where string, args ...interface{}) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM rituals.pending_mls_removals WHERE `+where, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`user_id = $1`, s.bob); n != 4 {
		t.Fatalf("pending rows for bob = %d, want 4", n)
	}
	if n := count(`user_id = $1`, s.alice); n != 0 {
		t.Fatalf("pending rows for alice = %d", n)
	}

	// Replay to Alice: byte-identical frames, oldest first; Bob's own
	// subscribe gets nothing about himself.
	frames := s.rt.pendingRemovalFrames(ctx, s.textCh, s.alice)
	want := [][]byte{ritualsRemovalFrame(s.textCh, s.bob, "synthetic-bob-1"), ritualsRemovalFrame(s.textCh, s.bob, "synthetic-bob-2")}
	if len(frames) != 2 || !bytes.Equal(frames[0], want[0]) || !bytes.Equal(frames[1], want[1]) {
		t.Fatalf("replay = %q", frames)
	}
	if !strings.Contains(string(frames[0]), `"action":"remove"`) {
		t.Fatalf("frame shape %s", frames[0])
	}
	if f := s.rt.pendingRemovalFrames(ctx, s.textCh, s.bob); len(f) != 0 {
		t.Fatalf("self replay = %q", f)
	}
	if f := s.rt.pendingRemovalFrames(ctx, "not-a-uuid", s.alice); f != nil {
		t.Fatalf("bad channel id replay = %q", f)
	}

	// TTL: an expired record is neither replayed nor kept by the next sync.
	if _, err := pool.Exec(ctx, `UPDATE rituals.pending_mls_removals SET created_at = now() - interval '31 days'
		WHERE channel_id = $1 AND device_id = 'synthetic-bob-2'`, text2); err != nil {
		t.Fatal(err)
	}
	if f := s.rt.pendingRemovalFrames(ctx, text2, s.alice); len(f) != 1 {
		t.Fatalf("expired record replayed: %q", f)
	}
	s.now = s.now.Add(time.Second)
	if _, err := s.rt.applySync(ctx, &ritualsSync{V: 1, Aud: "https://space.rit.al", Sp: s.sp, Subs: []string{s.subA},
		Iat: s.now.Unix(), Exp: s.now.Unix() + 600}); err != nil {
		t.Fatal(err)
	}
	if n := count(`user_id = $1`, s.bob); n != 3 {
		t.Fatalf("after TTL sweep = %d, want 3", n)
	}

	// Deleting a channel cascades its records.
	if _, err := pool.Exec(ctx, `DELETE FROM channels WHERE id = $1`, text2); err != nil {
		t.Fatal(err)
	}
	if n := count(`user_id = $1`, s.bob); n != 2 {
		t.Fatalf("after channel delete = %d, want 2", n)
	}

	// Re-invited: a newer sync allows Bob again and his claim clears his records.
	s.now = s.now.Add(time.Second)
	if _, err := s.rt.applySync(ctx, &ritualsSync{V: 1, Aud: "https://space.rit.al", Sp: s.sp, Subs: []string{s.subA, s.subB},
		Iat: s.now.Unix(), Exp: s.now.Unix() + 600}); err != nil {
		t.Fatal(err)
	}
	s.now = s.now.Add(time.Second)
	s.claim(t, s.bob, s.subB, "member")
	if n := count(`user_id = $1`, s.bob); n != 0 {
		t.Fatalf("after re-seat = %d, want 0", n)
	}
}
