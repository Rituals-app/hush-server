package api

// Rituals fork: the per-person device (seat) cap, the person-counted member
// cap, selfSeated only for seats with a member row, and one "left" line per
// removed person. The DB tests run against TEST_DATABASE_URL (skipped when
// unset) with synthetic users only.

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/hushhq/hush-server/internal/db"
)

func TestRitualsOnePerPerson(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	seats := map[string]struct {
		sub string
		at  time.Time
	}{
		"u1": {"a", base},
		"u2": {"b", base},
		"u3": {"a", base.Add(time.Minute)},
		"u4": {"a", base.Add(-time.Minute)},
		"u5": {"c", base},
	}
	got := ritualsOnePerPerson([]string{"u1", "u2", "u3", "u4", "u5"}, func(uid string) (string, time.Time) {
		return seats[uid].sub, seats[uid].at
	})
	want := []string{"u3", "u2", "u5"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if out := ritualsOnePerPerson(nil, nil); len(out) != 0 {
		t.Fatalf("empty input gave %v", out)
	}
}

func ritualsSeatsOf(t *testing.T, s *ritualsTestSpace, sub string) []string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(),
		`SELECT user_id::text FROM rituals.seats WHERE sp = $1 AND sub = $2 ORDER BY user_id`, s.sp, sub)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			t.Fatal(err)
		}
		out = append(out, uid)
	}
	return out
}

func ritualsIsMember(t *testing.T, s *ritualsTestSpace, uid string) bool {
	t.Helper()
	var ok bool
	if err := s.pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2)`, s.serverID, uid).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

// ritualsSeatAge backdates a seat so the retirement order is deterministic.
func ritualsSeatAge(t *testing.T, s *ritualsTestSpace, uid string, ago time.Duration) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(),
		`UPDATE rituals.seats SET created_at = now() - make_interval(secs => $3) WHERE sp = $1 AND user_id = $2`,
		s.sp, uid, ago.Seconds()); err != nil {
		t.Fatal(err)
	}
}

func ritualsSystemEvents(frames []map[string]interface{}) (events []string, actors []string) {
	for _, f := range frames {
		if f["type"] != "system_message" {
			continue
		}
		m, _ := f["system_message"].(map[string]interface{})
		ev, _ := m["eventType"].(string)
		actor, _ := m["actorId"].(string)
		events = append(events, ev)
		actors = append(actors, actor)
	}
	return events, actors
}

func ritualsFramesOfType(frames []map[string]interface{}, typ string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, f := range frames {
		if f["type"] == typ {
			out = append(out, f)
		}
	}
	return out
}

func TestRitualsDeviceCapRetiresLeastRecentDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool) // alice (subA, owner) and bob (subB)
	hub := &ritualsRecordingHub{}
	s.rt.hub = hub
	s.rt.personSecret = ritualsPersonKeySecret("synthetic-jwt-secret-for-tests-only")
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	// Alice on five devices. Seat ages: alice oldest ... d4 newest.
	devices := []string{s.alice}
	for i := 0; i < 4; i++ {
		uid := s.user(t)
		s.claim(t, uid, s.subA, "member")
		devices = append(devices, uid)
	}
	for i, uid := range devices {
		ritualsSeatAge(t, s, uid, time.Duration(50-i*10)*time.Minute)
		s.device(t, uid, "dev-"+uid[:8])
	}
	// The oldest seat signed in a moment ago, so the least recently active
	// one is the second oldest.
	if _, err := pool.Exec(ctx, `INSERT INTO device_keys (user_id, device_id, device_public_key, last_seen)
		VALUES ($1, 'k1', '\x00', now())`, s.alice); err != nil {
		t.Fatal(err)
	}
	stale := devices[1]
	hub.take()

	sixth := s.user(t)
	res, cerr, err := s.rt.claimSpace(ctx, sixth, ritualsTestTicket(t, s.priv, s.now, s.sp, s.subA, "member"))
	if err != nil || cerr != nil {
		t.Fatalf("sixth device claim: %v %v", cerr, err)
	}
	if len(res.retired) != 1 || res.retired[0] != stale || len(res.retiredMembers) != 1 || res.retiredMembers[0] != stale {
		t.Fatalf("retired = %v members %v, want [%s]", res.retired, res.retiredMembers, stale)
	}
	if !res.memberInserted || !res.selfSeated {
		t.Fatalf("claim result: %+v", res)
	}
	seats := ritualsSeatsOf(t, s, s.subA)
	if len(seats) != ritualsSeatsPerPerson {
		t.Fatalf("alice holds %d seats, want %d", len(seats), ritualsSeatsPerPerson)
	}
	for _, uid := range seats {
		if uid == stale {
			t.Fatal("the least recently active seat survived")
		}
	}
	if ritualsIsMember(t, s, stale) || !ritualsIsMember(t, s, sixth) || !ritualsIsMember(t, s, s.alice) {
		t.Fatal("member rows after retirement")
	}
	var pending int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM rituals.pending_mls_removals WHERE user_id = $1 AND channel_id = $2`,
		stale, s.textCh).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("pending MLS removals for the retired seat = %d %v", pending, err)
	}
	var memberCount, rowsNow int
	if err := pool.QueryRow(ctx, `SELECT member_count, (SELECT COUNT(*) FROM server_members WHERE server_id = $1)
		FROM servers WHERE id = $1`, s.serverID).Scan(&memberCount, &rowsNow); err != nil || memberCount != rowsNow {
		t.Fatalf("member_count = %d, rows = %d %v", memberCount, rowsNow, err)
	}

	// After commit: the retired device is kicked, nobody "left", and the new
	// device gets the quiet new-device line.
	s.rt.announceClaim(ctx, sixth, res)
	frames := hub.take()
	kicked := ritualsFramesOfType(frames, "member_kicked")
	if len(kicked) != 1 || kicked[0]["user_id"] != stale {
		t.Fatalf("member_kicked frames = %v", kicked)
	}
	events, _ := ritualsSystemEvents(frames)
	if len(events) != 1 || events[0] != "member_new_device" {
		t.Fatalf("system events = %v", events)
	}
	if joined := ritualsFramesOfType(frames, "member_joined"); len(joined) != 1 {
		t.Fatalf("member_joined frames = %d", len(joined))
	}

	// Re-opening on a device that still holds a seat retires nothing.
	res, cerr, err = s.rt.claimSpace(ctx, s.alice, ritualsTestTicket(t, s.priv, s.now, s.sp, s.subA, "owner"))
	if err != nil || cerr != nil || len(res.retired) != 0 {
		t.Fatalf("re-open: %+v %v %v", res, cerr, err)
	}
	// Bob is untouched throughout.
	if got := ritualsSeatsOf(t, s, s.subB); len(got) != 1 || got[0] != s.bob || !ritualsIsMember(t, s, s.bob) {
		t.Fatalf("bob seats = %v", got)
	}
}

func TestRitualsDeviceCapTrimsOverCapPersonDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool)

	// Seats from before the cap: Alice holds 8 (written directly).
	for i := 0; i < 7; i++ {
		uid := s.user(t)
		if _, err := pool.Exec(ctx, `INSERT INTO rituals.seats (sp, sub, user_id, created_at) VALUES ($1, $2, $3, now() - interval '1 hour')`,
			s.sp, s.subA, uid); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO server_members (server_id, user_id, permission_level) VALUES ($1, $2, 0)`,
			s.serverID, uid); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(ritualsSeatsOf(t, s, s.subA)); got != 8 {
		t.Fatalf("setup seats = %d", got)
	}
	next := s.user(t)
	res, cerr, err := s.rt.claimSpace(ctx, next, ritualsTestTicket(t, s.priv, s.now, s.sp, s.subA, "member"))
	if err != nil || cerr != nil {
		t.Fatalf("claim: %v %v", cerr, err)
	}
	if len(res.retired) != 4 || len(res.retiredMembers) != 4 {
		t.Fatalf("retired %d (members %d), want 4", len(res.retired), len(res.retiredMembers))
	}
	for _, uid := range res.retired {
		if uid == next || uid == s.alice {
			// Alice's own seat is the newest by created_at here.
			t.Fatalf("retired %s", uid)
		}
	}
	if got := len(ritualsSeatsOf(t, s, s.subA)); got != ritualsSeatsPerPerson {
		t.Fatalf("seats after claim = %d", got)
	}
}

func TestRitualsMemberCapCountsPeopleDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool) // 2 people, 2 devices

	// Alice adds two devices: 2 people on 4 devices.
	for i := 0; i < 2; i++ {
		s.claim(t, s.user(t), s.subA, "member")
	}
	// 62 more people fill the space to 64 people on 66 devices, past the old
	// 64-device limit.
	for i := 0; i < ritualsSpaceMemberCap-2; i++ {
		s.claim(t, s.user(t), ritualsTestHex(t, 32), "member")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	people, err := ritualsPeopleCount(ctx, tx, s.sp, s.serverID)
	_ = tx.Rollback(ctx)
	if err != nil || people != ritualsSpaceMemberCap {
		t.Fatalf("people = %d %v", people, err)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM server_members WHERE server_id = $1`, s.serverID).Scan(&rows); err != nil || rows != ritualsSpaceMemberCap+2 {
		t.Fatalf("member rows = %d %v", rows, err)
	}

	// A 65th person is refused, and nothing of theirs is written.
	late := s.user(t)
	lateSub := ritualsTestHex(t, 32)
	if _, cerr, err := s.rt.claimSpace(ctx, late, ritualsTestTicket(t, s.priv, s.now, s.sp, lateSub, "member")); err != nil || cerr == nil || cerr.code != "space_full" {
		t.Fatalf("65th person: %v %v", cerr, err)
	}
	if len(ritualsSeatsOf(t, s, lateSub)) != 0 {
		t.Fatal("refused claim left a seat")
	}
	// A further device of a person already here still gets in.
	if _, cerr, err := s.rt.claimSpace(ctx, s.user(t), ritualsTestTicket(t, s.priv, s.now, s.sp, s.subB, "member")); err != nil || cerr != nil {
		t.Fatalf("existing person's new device: %v %v", cerr, err)
	}
	// A member row without a seat (a non-Rituals member) counts as a person.
	if _, err := pool.Exec(ctx, `DELETE FROM rituals.seats WHERE sp = $1 AND user_id = $2`, s.sp, s.bob); err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	people, err = ritualsPeopleCount(ctx, tx, s.sp, s.serverID)
	_ = tx.Rollback(ctx)
	// Bob's other device still carries subB, and his unseated row counts once.
	if err != nil || people != ritualsSpaceMemberCap+1 {
		t.Fatalf("people with an unseated row = %d %v", people, err)
	}
}

func TestRitualsSelfSeatedNeedsMemberRowDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool)
	hub := &ritualsRecordingHub{}
	s.rt.hub = hub
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	// Alice's only device lost its member row (an in-frame kick) but keeps
	// its seat: a new device of hers is not "already here".
	if _, err := pool.Exec(ctx, `DELETE FROM server_members WHERE server_id = $1 AND user_id = $2`, s.serverID, s.alice); err != nil {
		t.Fatal(err)
	}
	second := s.user(t)
	res, cerr, err := s.rt.claimSpace(ctx, second, ritualsTestTicket(t, s.priv, s.now, s.sp, s.subA, "member"))
	if err != nil || cerr != nil || res.selfSeated || !res.memberInserted {
		t.Fatalf("claim: %+v %v %v", res, cerr, err)
	}
	s.rt.announceClaim(ctx, second, res)
	if events, _ := ritualsSystemEvents(hub.take()); len(events) != 1 || events[0] != "member_joined" {
		t.Fatalf("system events = %v", events)
	}
	// With a member row on the other device it is a new device again.
	third := s.user(t)
	res, cerr, err = s.rt.claimSpace(ctx, third, ritualsTestTicket(t, s.priv, s.now, s.sp, s.subA, "member"))
	if err != nil || cerr != nil || !res.selfSeated {
		t.Fatalf("third device: %+v %v %v", res, cerr, err)
	}
}

func TestRitualsSyncOneLeftLinePerPersonDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool)
	hub := &ritualsRecordingHub{}
	s.rt.hub = hub
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	aliceTwo := s.user(t)
	s.claim(t, aliceTwo, s.subA, "member")
	ritualsSeatAge(t, s, s.alice, time.Hour)
	carol, subC := s.user(t), ritualsTestHex(t, 32)
	s.claim(t, carol, subC, "member")
	hub.take()

	// Alice (two devices) and Carol leave the task.
	s.now = s.now.Add(time.Second)
	res, err := s.rt.applySync(ctx, &ritualsSync{V: 1, Aud: "https://space.rit.al", Sp: s.sp,
		Subs: []string{s.subB}, Iat: s.now.Unix(), Exp: s.now.Unix() + 600})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.removedMembers) != 3 {
		t.Fatalf("removed members = %v", res.removedMembers)
	}
	left := append([]string(nil), res.leftActors...)
	sort.Strings(left)
	want := []string{aliceTwo, carol}
	sort.Strings(want)
	if len(left) != 2 || left[0] != want[0] || left[1] != want[1] {
		t.Fatalf("left actors = %v, want %v (Alice's newest device and Carol)", left, want)
	}
	s.rt.announceSync(res)
	frames := hub.take()
	if kicked := ritualsFramesOfType(frames, "member_kicked"); len(kicked) != 3 {
		t.Fatalf("member_kicked frames = %d, want one per device", len(kicked))
	}
	events, actors := ritualsSystemEvents(frames)
	if len(events) != 2 || events[0] != "member_left" || events[1] != "member_left" {
		t.Fatalf("system events = %v", events)
	}
	sort.Strings(actors)
	if actors[0] != want[0] || actors[1] != want[1] {
		t.Fatalf("left line actors = %v", actors)
	}
}
