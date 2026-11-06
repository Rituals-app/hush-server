package api

// Rituals fork: the per-Space person key, the new-device system line and
// revoke of every seat of a person. The DB test runs against
// TEST_DATABASE_URL (skipped when unset) with synthetic users only.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hushhq/hush-server/internal/db"
)

func TestRitualsPersonKey(t *testing.T) {
	rt := &ritualsRuntime{personSecret: ritualsPersonKeySecret("synthetic-jwt-secret-for-tests-only")}
	spA, spB := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	subA, subB := strings.Repeat("cc", 32), strings.Repeat("dd", 32)
	k := rt.personKey(spA, subA)
	if k == "" || k != rt.personKey(spA, subA) {
		t.Fatalf("key not stable: %q", k)
	}
	if k == rt.personKey(spB, subA) {
		t.Fatal("same key across spaces")
	}
	if k == rt.personKey(spA, subB) {
		t.Fatal("same key for two people")
	}
	if strings.Contains(k, subA) || strings.Contains(k, spA) || len(k) != 22 {
		t.Fatalf("key not opaque: %q", k)
	}
	other := &ritualsRuntime{personSecret: ritualsPersonKeySecret("another-synthetic-secret-value")}
	if other.personKey(spA, subA) == k {
		t.Fatal("key does not depend on the server secret")
	}
	if (&ritualsRuntime{}).personKey(spA, subA) != "" || ritualsPersonKeySecret("") != nil {
		t.Fatal("no secret must give no key")
	}
	if ritualsJoinEventType(&ritualsClaimResult{}) != "member_joined" ||
		ritualsJoinEventType(&ritualsClaimResult{selfSeated: true}) != "member_new_device" {
		t.Fatal("join event type")
	}
}

type ritualsRecordingHub struct {
	mu     sync.Mutex
	frames []map[string]interface{}
	// connected is the set of users ConnectedUsers reports as online.
	connected map[string]bool
}

func (h *ritualsRecordingHub) record(message []byte) {
	var m map[string]interface{}
	_ = json.Unmarshal(message, &m)
	h.mu.Lock()
	h.frames = append(h.frames, m)
	h.mu.Unlock()
}
func (h *ritualsRecordingHub) BroadcastToAll(message []byte)                     { h.record(message) }
func (h *ritualsRecordingHub) BroadcastToServer(_ string, message []byte)        { h.record(message) }
func (h *ritualsRecordingHub) BroadcastToUser(string, []byte)                    {}
func (h *ritualsRecordingHub) DisconnectUser(string)                             {}
func (h *ritualsRecordingHub) DisconnectDevice(string, string)                   {}
func (h *ritualsRecordingHub) Broadcast(string, []byte, string)                  {}
func (h *ritualsRecordingHub) DisconnectUserFromServer(string, string, []string) {}
func (h *ritualsRecordingHub) SetSubscribeHook(func(context.Context, string, string) [][]byte) {
}
func (h *ritualsRecordingHub) ConnectedUsers(userIDs []string) map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]bool{}
	for _, id := range userIDs {
		if h.connected[id] {
			out[id] = true
		}
	}
	return out
}

func (h *ritualsRecordingHub) take() []map[string]interface{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.frames
	h.frames = nil
	return out
}

func TestRitualsPersonKeyMembersDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool) // alice (subA, owner) and bob (subB)
	hub := &ritualsRecordingHub{}
	s.rt.hub = hub
	s.rt.personSecret = ritualsPersonKeySecret("synthetic-jwt-secret-for-tests-only")
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	// Alice opens the space on a second device: one quiet line, not a join.
	aliceTwo := s.user(t)
	res, cerr, err := s.rt.claimSpace(ctx, aliceTwo, ritualsTestTicket(t, s.priv, s.now, s.sp, s.subA, "member"))
	if err != nil || cerr != nil || !res.memberInserted || !res.selfSeated {
		t.Fatalf("second device claim: %+v %v %v", res, cerr, err)
	}
	s.rt.announceClaim(ctx, aliceTwo, res)
	var joined, sys map[string]interface{}
	for _, f := range hub.take() {
		switch f["type"] {
		case "member_joined":
			joined = f
		case "system_message":
			sys = f
		}
	}
	if joined == nil || sys == nil {
		t.Fatalf("frames missing: joined=%v sys=%v", joined, sys)
	}
	if got := joined["member"].(map[string]interface{})["personKey"]; got != s.rt.personKey(s.sp, s.subA) {
		t.Fatalf("member_joined personKey = %v", got)
	}
	if got := sys["system_message"].(map[string]interface{})["eventType"]; got != "member_new_device" {
		t.Fatalf("system event = %v", got)
	}
	// A first seat of a new person keeps today's line.
	carol := s.user(t)
	subC := ritualsTestHex(t, 32)
	res, cerr, err = s.rt.claimSpace(ctx, carol, ritualsTestTicket(t, s.priv, s.now, s.sp, subC, "member"))
	if err != nil || cerr != nil || res.selfSeated {
		t.Fatalf("carol claim: %+v %v %v", res, cerr, err)
	}
	s.rt.announceClaim(ctx, carol, res)
	for _, f := range hub.take() {
		if f["type"] == "system_message" {
			if got := f["system_message"].(map[string]interface{})["eventType"]; got != "member_joined" {
				t.Fatalf("first seat event = %v", got)
			}
		}
	}

	// Member list: both Alice devices share one key, others differ.
	// A non-Rituals member of the same guild (no seat) gets no key.
	plain := s.user(t)
	if _, err := pool.Exec(ctx, `INSERT INTO server_members (server_id, user_id, permission_level) VALUES ($1, $2, 0)`,
		s.serverID, plain); err != nil {
		t.Fatal(err)
	}
	members, err := pool.ListServerMembers(ctx, s.serverID)
	if err != nil {
		t.Fatal(err)
	}
	ritualsAnnotateMembers(ctx, s.serverID, members)
	keys := map[string]string{}
	for _, m := range members {
		keys[m.ID] = m.PersonKey
	}
	if keys[s.alice] == "" || keys[s.alice] != keys[aliceTwo] || keys[s.alice] == keys[s.bob] ||
		keys[carol] == "" || keys[carol] == keys[s.alice] {
		t.Fatalf("keys = %v", keys)
	}
	if k, ok := keys[plain]; !ok || k != "" {
		t.Fatalf("non-Rituals member key = %q (present %v)", k, ok)
	}
	raw, _ := json.Marshal(members)
	if strings.Contains(string(raw), s.subA) {
		t.Fatal("member payload leaks the sub")
	}
	// Outside RITUALS_MODE the list is untouched.
	ritualsCurrent.Store(nil)
	again, _ := pool.ListServerMembers(ctx, s.serverID)
	ritualsAnnotateMembers(ctx, s.serverID, again)
	for _, m := range again {
		if m.PersonKey != "" {
			t.Fatal("key outside rituals mode")
		}
	}
	ritualsCurrent.Store(s.rt)

	// D1: a sync without Alice removes every seat of hers.
	s.now = s.now.Add(time.Second)
	sres, err := s.rt.applySync(ctx, &ritualsSync{V: 1, Aud: "https://space.rit.al", Sp: s.sp,
		Subs: []string{s.subB, subC}, Iat: s.now.Unix(), Exp: s.now.Unix() + 600})
	if err != nil {
		t.Fatal(err)
	}
	removed := append([]string(nil), sres.removedMembers...)
	sort.Strings(removed)
	want := []string{s.alice, aliceTwo}
	sort.Strings(want)
	if len(removed) != 2 || removed[0] != want[0] || removed[1] != want[1] {
		t.Fatalf("removed = %v, want both Alice devices %v", removed, want)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM server_members WHERE server_id = $1 AND user_id = ANY($2)`,
		s.serverID, want).Scan(&left); err != nil || left != 0 {
		t.Fatalf("alice rows left = %d %v", left, err)
	}
}
