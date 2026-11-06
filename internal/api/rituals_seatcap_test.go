package api

// Rituals fork: the per-person device (seat) cap, the person-counted member
// cap, selfSeated only for seats with a member row, and one "left" line per
// removed person. The DB tests run against TEST_DATABASE_URL (skipped when
// unset) with synthetic users only.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

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

// ritualsSeatAge backdates a seat's creation and last activity so the
// retirement order is deterministic.
func ritualsSeatAge(t *testing.T, s *ritualsTestSpace, uid string, ago time.Duration) {
	t.Helper()
	ritualsSeatTimes(t, s, uid, ago, ago)
}

// ritualsSeatTimes sets a seat's created_at and last_active_at to now minus
// created and active.
func ritualsSeatTimes(t *testing.T, s *ritualsTestSpace, uid string, created, active time.Duration) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `
		UPDATE rituals.seats SET created_at = now() - make_interval(secs => $3),
		                         last_active_at = now() - make_interval(secs => $4)
		WHERE sp = $1 AND user_id = $2`,
		s.sp, uid, created.Seconds(), active.Seconds()); err != nil {
		t.Fatal(err)
	}
}

// ritualsLastActiveAgo is how long ago the seat's last_active_at is, or -1
// when it is NULL.
func ritualsLastActiveAgo(t *testing.T, s *ritualsTestSpace, uid string) time.Duration {
	t.Helper()
	var secs *float64
	if err := s.pool.QueryRow(context.Background(), `
		SELECT EXTRACT(EPOCH FROM now() - last_active_at)::float8 FROM rituals.seats WHERE sp = $1 AND user_id = $2`,
		s.sp, uid).Scan(&secs); err != nil {
		t.Fatal(err)
	}
	if secs == nil {
		return -1
	}
	return time.Duration(*secs * float64(time.Second))
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
	// The oldest seat's device subscribed to the space a moment ago (the
	// hub's server activity hook), so the least recently active one is the
	// second oldest.
	s.rt.touchSeatActivity(ctx, s.alice, []string{s.serverID})
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
	if len(kicked) != 1 || kicked[0]["user_id"] != stale || kicked[0]["reason"] != "device_limit" {
		t.Fatalf("member_kicked frames = %v", kicked)
	}
	events, _ := ritualsSystemEvents(frames)
	if len(events) != 1 || events[0] != "member_new_device" {
		t.Fatalf("system events = %v", events)
	}
	if joined := ritualsFramesOfType(frames, "member_joined"); len(joined) != 1 {
		t.Fatalf("member_joined frames = %d", len(joined))
	}
	// The deferred per-server disconnect carries the reason too, for a
	// connection of the retired device that was not subscribed.
	if got := hub.takeDisconnects(1, 3*time.Second); len(got) != 1 || got[0] != stale+"/"+s.serverID+"/device_limit" {
		t.Fatalf("disconnects = %v", got)
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

// ritualsClaimRetires claims a new device for sub and returns what it retired.
func ritualsClaimRetires(t *testing.T, s *ritualsTestSpace, uid, sub string) *ritualsClaimResult {
	t.Helper()
	res, cerr, err := s.rt.claimSpace(context.Background(), uid, ritualsTestTicket(t, s.priv, s.now, s.sp, sub, "member"))
	if err != nil || cerr != nil {
		t.Fatalf("claim: %v %v", cerr, err)
	}
	if got := len(ritualsSeatsOf(t, s, sub)); got != ritualsSeatsPerPerson {
		t.Fatalf("seats after claim = %d, want %d", got, ritualsSeatsPerPerson)
	}
	return res
}

// The device cap spares a device in use and retires seats that never
// finished joining first: a private window or wiped account that registered
// (no MLS credential) or lost its member row, then the least recently active
// by last_active_at; only when every other seat is connected does it fall
// back to the activity order.
func TestRitualsDeviceCapSparesConnectedDevicesDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool) // alice (subA, owner) and bob (subB)
	hub := &ritualsRecordingHub{connected: map[string]bool{}}
	s.rt.hub = hub
	s.rt.personSecret = ritualsPersonKeySecret("synthetic-jwt-secret-for-tests-only")
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	// Alice's daily laptop holds the oldest seat and is connected now, with no
	// recent sign-in. d2 is a private window that registered and closed
	// before uploading an MLS credential.
	devices := []string{s.alice}
	for i := 0; i < 4; i++ {
		uid := s.user(t)
		s.claim(t, uid, s.subA, "member")
		devices = append(devices, uid)
	}
	alice, d1, d2, d3, d4 := devices[0], devices[1], devices[2], devices[3], devices[4]
	for i, uid := range devices {
		ritualsSeatAge(t, s, uid, time.Duration(50-i*10)*time.Minute)
		if uid != d2 {
			s.device(t, uid, "dev-"+uid[:8])
		}
	}
	hub.connected[alice] = true
	hub.take()

	// 1. The unfinished seat goes, not the older connected laptop nor the
	// older finished d1.
	sixth := s.user(t)
	res := ritualsClaimRetires(t, s, sixth, s.subA)
	if len(res.retired) != 1 || res.retired[0] != d2 || len(res.retiredMembers) != 1 || res.retiredMembers[0] != d2 {
		t.Fatalf("retired %v (members %v), want the unfinished seat %s", res.retired, res.retiredMembers, d2)
	}
	if !ritualsIsMember(t, s, alice) || !ritualsIsMember(t, s, d1) {
		t.Fatal("a finished seat lost its member row")
	}
	s.rt.announceClaim(ctx, sixth, res)
	kicked := ritualsFramesOfType(hub.take(), "member_kicked")
	if len(kicked) != 1 || kicked[0]["user_id"] != d2 || kicked[0]["reason"] != "device_limit" {
		t.Fatalf("member_kicked frames = %v", kicked)
	}
	s.device(t, sixth, "dev-"+sixth[:8])

	// 2. A seat whose member row is gone (kicked in the frame) is unfinished
	// too and goes before the least recently active d1.
	if _, err := pool.Exec(ctx, `DELETE FROM server_members WHERE server_id = $1 AND user_id = $2`, s.serverID, d4); err != nil {
		t.Fatal(err)
	}
	seventh := s.user(t)
	res = ritualsClaimRetires(t, s, seventh, s.subA)
	if len(res.retired) != 1 || res.retired[0] != d4 || len(res.retiredMembers) != 0 {
		t.Fatalf("retired %v (members %v), want the seat without a member row %s", res.retired, res.retiredMembers, d4)
	}
	s.device(t, seventh, "dev-"+seventh[:8])

	// 3. d1's connection unsubscribed a moment ago (the hub's server activity
	// hook), so the least recently active unconnected seat is d3.
	s.rt.touchSeatActivity(ctx, d1, []string{s.serverID})
	eighth := s.user(t)
	res = ritualsClaimRetires(t, s, eighth, s.subA)
	if len(res.retired) != 1 || res.retired[0] != d3 {
		t.Fatalf("retired %v, want %s (d1 is recent by last_active_at)", res.retired, d3)
	}
	s.device(t, eighth, "dev-"+eighth[:8])

	// 4. Every other seat is connected: the cap still holds, and the least
	// recently active connected seat (the laptop) goes.
	for _, uid := range ritualsSeatsOf(t, s, s.subA) {
		hub.connected[uid] = true
	}
	ninth := s.user(t)
	res = ritualsClaimRetires(t, s, ninth, s.subA)
	if len(res.retired) != 1 || res.retired[0] != alice {
		t.Fatalf("retired %v, want the least recently active %s", res.retired, alice)
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
			// The seven direct inserts have no MLS credentials and are past
			// the join grace (unfinished); Alice's own seat is inside it.
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
	kicked := ritualsFramesOfType(frames, "member_kicked")
	if len(kicked) != 3 {
		t.Fatalf("member_kicked frames = %d, want one per device", len(kicked))
	}
	for _, f := range kicked {
		// A revoke is a plain kick: no reason, unlike the device cap.
		if _, ok := f["reason"]; ok {
			t.Fatalf("revoke kick has a reason: %v", f)
		}
	}
	disconnects := hub.takeDisconnects(3, 3*time.Second)
	if len(disconnects) != 3 {
		t.Fatalf("disconnects = %v, want one per device", disconnects)
	}
	for _, d := range disconnects {
		if !strings.HasSuffix(d, "/"+s.serverID+"/") {
			t.Fatalf("revoke disconnect has a reason: %s", d)
		}
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

// ritualsFiveDevices gives alice four more seated devices (five in all, the
// cap), each with an MLS credential, and returns them oldest seat first.
func ritualsFiveDevices(t *testing.T, s *ritualsTestSpace) []string {
	t.Helper()
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
	return devices
}

// Fix round 2: the cap ranks unconnected seats by recent use, and recent
// activity in the space counts, not only when the seat was made or the device
// last signed in. An old seat whose device was in the space a minute ago
// stays; a newer one nobody opened since goes.
func TestRitualsDeviceCapRanksByLastActiveDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool) // alice (subA, owner) and bob (subB)
	hub := &ritualsRecordingHub{connected: map[string]bool{}}
	s.rt.hub = hub
	s.rt.personSecret = ritualsPersonKeySecret("synthetic-jwt-secret-for-tests-only")
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	devices := ritualsFiveDevices(t, s)
	alice, oldActive, d2, d3, newIdle := devices[0], devices[1], devices[2], devices[3], devices[4]
	ritualsSeatTimes(t, s, alice, 50*time.Minute, 5*time.Minute)
	// Seated three days ago, last in the space two hours ago, then its
	// connection subscribed to the space just now.
	ritualsSeatTimes(t, s, oldActive, 72*time.Hour, 2*time.Hour)
	ritualsSeatTimes(t, s, d2, 30*time.Minute, 10*time.Minute)
	ritualsSeatTimes(t, s, d3, 20*time.Minute, 10*time.Minute)
	// Seated an hour ago and idle since: the newer seat, but the stalest.
	ritualsSeatTimes(t, s, newIdle, time.Hour, time.Hour)
	s.rt.touchSeatActivity(ctx, oldActive, []string{s.serverID})
	if ago := ritualsLastActiveAgo(t, s, oldActive); ago < 0 || ago > 30*time.Second {
		t.Fatalf("subscribe did not stamp last_active_at: %v ago", ago)
	}
	// Under the creation / sign-in recency the oldest seat would go.
	var oldPick string
	if err := pool.QueryRow(ctx, `
		SELECT s.user_id::text FROM rituals.seats s WHERE s.sp = $1 AND s.sub = $2
		ORDER BY GREATEST(s.created_at,
		         (SELECT MAX(dk.last_seen) FROM device_keys dk WHERE dk.user_id = s.user_id),
		         (SELECT MAX(d.last_seen) FROM devices d WHERE d.user_id = s.user_id)) LIMIT 1`,
		s.sp, s.subA).Scan(&oldPick); err != nil || oldPick != oldActive {
		t.Fatalf("setup: old ranking picks %s %v, want %s", oldPick, err, oldActive)
	}

	sixth := s.user(t)
	res := ritualsClaimRetires(t, s, sixth, s.subA)
	if len(res.retired) != 1 || res.retired[0] != newIdle {
		t.Fatalf("retired %v, want the idle seat %s (not the old but active %s)", res.retired, newIdle, oldActive)
	}
	if ago := ritualsLastActiveAgo(t, s, sixth); ago < 0 || ago > 30*time.Second {
		t.Fatalf("a new seat starts active now: %v ago", ago)
	}

	// Inside the connected tier the same order holds: everyone online, the
	// least recently active connected seat goes (d2, d3 tie at 10 minutes and
	// the older seat breaks it).
	for _, uid := range ritualsSeatsOf(t, s, s.subA) {
		hub.connected[uid] = true
	}
	s.device(t, sixth, "dev-"+sixth[:8])
	res = ritualsClaimRetires(t, s, s.user(t), s.subA)
	if len(res.retired) != 1 || res.retired[0] != d2 {
		t.Fatalf("connected tier retired %v, want %s", res.retired, d2)
	}
}

// Fix round 2: claims and the hub's server activity hook stamp
// last_active_at; the hook only rewrites a value older than the throttle,
// only for that user's seats in the given servers, and ignores bad ids.
func TestRitualsSeatActivityTouchDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool) // alice (subA, owner) and bob (subB)
	hub := &ritualsRecordingHub{}
	s.rt.hub = hub
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	// A re-open of an existing seat counts as activity.
	ritualsSeatAge(t, s, s.alice, time.Hour)
	s.claim(t, s.alice, s.subA, "owner")
	if ago := ritualsLastActiveAgo(t, s, s.alice); ago < 0 || ago > 30*time.Second {
		t.Fatalf("re-open did not stamp last_active_at: %v ago", ago)
	}

	// Throttle: 30 s old stays, 90 s old (or NULL) is rewritten.
	ritualsSeatAge(t, s, s.alice, 30*time.Second)
	ritualsSeatAge(t, s, s.bob, time.Hour)
	s.rt.touchSeatActivity(ctx, s.alice, []string{s.serverID})
	if ago := ritualsLastActiveAgo(t, s, s.alice); ago < 25*time.Second {
		t.Fatalf("a 30 s old value was rewritten (%v ago)", ago)
	}
	if ago := ritualsLastActiveAgo(t, s, s.bob); ago < 50*time.Minute {
		t.Fatalf("another user's seat was touched (%v ago)", ago)
	}
	ritualsSeatAge(t, s, s.alice, 90*time.Second)
	s.rt.touchSeatActivity(ctx, s.alice, []string{"not-a-uuid", s.serverID})
	if ago := ritualsLastActiveAgo(t, s, s.alice); ago < 0 || ago > 30*time.Second {
		t.Fatalf("a 90 s old value was not rewritten (%v ago)", ago)
	}
	if _, err := pool.Exec(ctx, `UPDATE rituals.seats SET last_active_at = NULL WHERE sp = $1 AND user_id = $2`, s.sp, s.bob); err != nil {
		t.Fatal(err)
	}
	s.rt.touchSeatActivity(ctx, "not-a-uuid", []string{s.serverID})
	s.rt.touchSeatActivity(ctx, s.bob, []string{"not-a-uuid"})
	s.rt.touchSeatActivity(ctx, s.bob, nil)
	if ago := ritualsLastActiveAgo(t, s, s.bob); ago != -1 {
		t.Fatalf("bad ids touched a seat (%v ago)", ago)
	}
	// Another space's server id does not touch this space's seat.
	other := newRitualsTestSpace(t, pool)
	s.rt.touchSeatActivity(ctx, s.bob, []string{other.serverID})
	if ago := ritualsLastActiveAgo(t, s, s.bob); ago != -1 {
		t.Fatalf("another server's activity touched this seat (%v ago)", ago)
	}
	s.rt.touchSeatActivity(ctx, s.bob, []string{other.serverID, s.serverID})
	if ago := ritualsLastActiveAgo(t, s, s.bob); ago < 0 || ago > 30*time.Second {
		t.Fatalf("NULL was not stamped (%v ago)", ago)
	}
	// A cancelled context is logged and dropped, never returned or panicked.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	s.rt.touchSeatActivity(cctx, s.alice, []string{s.serverID})

	// EnableRituals installs the hook on the hub, bound to the runtime it
	// builds (ritualsActive), and the hook stamps through that runtime's gate.
	ritualsCurrent.Store(nil)
	pub := s.priv.Public().(ed25519.PublicKey)
	if _, err := EnableRituals(RitualsOptions{
		SpaceOrigin:     "https://space.rit.al",
		TicketPublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Pool:            pool,
		Hub:             hub,
		JWTSecret:       "synthetic-jwt-secret-for-tests-only",
	}); err != nil {
		t.Fatal(err)
	}
	defer DisableRituals()
	rt := ritualsActive()
	if rt == nil || rt == s.rt {
		t.Fatal("EnableRituals did not build a new runtime")
	}
	gate := &rt.seatActivity
	defer ritualsWaitDrained(t, gate)
	hub.mu.Lock()
	hook := hub.activityHook
	hub.mu.Unlock()
	if hook == nil {
		t.Fatal("EnableRituals did not install the server activity hook")
	}
	// Each call returns at once: the hook only queues.
	quick := func(uid string, ids []string) {
		t.Helper()
		started := time.Now()
		hook(uid, ids)
		if took := time.Since(started); took > 100*time.Millisecond {
			t.Fatalf("the hook blocked for %v", took)
		}
	}
	ritualsSeatAge(t, s, s.bob, time.Hour)
	ritualsSeatAge(t, s, s.alice, time.Hour)
	quick(s.bob, []string{s.serverID})
	quick(s.alice, []string{"not-a-uuid", s.serverID})
	quick("not-a-uuid", []string{s.serverID})
	ritualsWaitStamped(t, s, s.bob)
	ritualsWaitStamped(t, s, s.alice)
	ritualsWaitDrained(t, gate)
	// Fix round 5: ids are canonical gate keys, so another spelling of the
	// same pair (upper case, braces) is throttled with it, not queued again.
	gate.mu.Lock()
	remembered := len(gate.seen)
	gate.mu.Unlock()
	quick(strings.ToUpper(s.bob), []string{"{" + strings.ToUpper(s.serverID) + "}"})
	gate.mu.Lock()
	_, same := gate.seen[ritualsSeatPair{s.bob, s.serverID}]
	seen, pending := len(gate.seen), len(gate.pending)
	gate.mu.Unlock()
	if !same || seen != remembered || pending != 0 {
		t.Fatalf("another spelling was a new pair (canonical key %v, seen %d -> %d, pending %d)", same, remembered, seen, pending)
	}
}

// Fix rounds 4 and 5: the hook never waits on the database. A seat row
// another transaction holds is skipped, not waited on, so it never stalls
// the batch. A write blocked any other way is cancelled on the server by the
// statement timeout (so it cannot land later) and retried after the gate's
// delay, and events that arrive meanwhile queue behind the one drainer.
func TestRitualsSeatActivityQueueDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool) // alice (subA, owner) and bob (subB)
	gate := &s.rt.seatActivity
	gate.retryDelay = 3 * time.Second
	defer ritualsWaitDrained(t, gate)
	state := func() (pending int, draining bool, retrying int) {
		gate.mu.Lock()
		defer gate.mu.Unlock()
		return len(gate.pending), gate.draining, gate.retrying
	}
	waitFor := func(within time.Duration, what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(within)
		for !ok() {
			if time.Now().After(deadline) {
				p, d, r := state()
				t.Fatalf("no %s within %v (pending %d, draining %v, retrying %d)", what, within, p, d, r)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	quick := func(uid string) {
		t.Helper()
		started := time.Now()
		s.rt.noteSeatActivity(uid, []string{s.serverID})
		if took := time.Since(started); took > 100*time.Millisecond {
			t.Fatalf("the hook blocked for %v", took)
		}
	}
	notStamped := func(when string, uids ...string) {
		t.Helper()
		for _, uid := range uids {
			if ago := ritualsLastActiveAgo(t, s, uid); ago < 50*time.Minute {
				t.Fatalf("%s: seat %s was stamped (%v ago)", when, uid, ago)
			}
		}
	}

	// A row lock: bob's seat is skipped, so alice's stamp lands at once, the
	// drain ends well inside the statement timeout, and nothing is retried
	// or left waiting to land when the lock goes.
	ritualsSeatAge(t, s, s.bob, time.Hour)
	ritualsSeatAge(t, s, s.alice, time.Hour)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM rituals.seats WHERE sp = $1 AND user_id = $2 FOR UPDATE`, s.sp, s.bob); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	quick(s.bob)
	quick(s.alice)
	waitFor(time.Second, "drain past a locked row", func() bool { p, d, _ := state(); return p == 0 && !d })
	if took := time.Since(started); took >= ritualsSeatActivityStatementTimeout {
		t.Fatalf("the drain waited on the row lock (%v)", took)
	}
	if _, _, r := state(); r != 0 {
		t.Fatalf("a skipped row was retried (%d timers)", r)
	}
	if ago := ritualsLastActiveAgo(t, s, s.alice); ago < 0 || ago > 30*time.Second {
		t.Fatalf("a locked row stalled the batch: alice not stamped (%v ago)", ago)
	}
	notStamped("row lock held", s.bob)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	notStamped("after the row lock", s.bob)

	// A table lock blocks the write itself (FOR NO KEY UPDATE takes ROW
	// SHARE, which EXCLUSIVE excludes; plain reads still pass). The gate
	// starts over first: alice and bob were queued a moment ago.
	gate.mu.Lock()
	gate.seen = nil
	gate.mu.Unlock()
	users := []string{s.alice, s.bob}
	for i := 0; i < 2; i++ {
		a, b := s.user(t), s.user(t)
		s.claim(t, a, s.subA, "member")
		s.claim(t, b, s.subB, "member")
		users = append(users, a, b)
	}
	for _, uid := range users {
		ritualsSeatAge(t, s, uid, time.Hour)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `LOCK TABLE rituals.seats IN EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	// The server cancels the blocked statement (57014, query_canceled)
	// before the client's bound, so it is not left waiting to land.
	started = time.Now()
	err = s.rt.touchSeatActivityPairs(ctx, []ritualsSeatPair{{s.alice, s.serverID}})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "57014" {
		t.Fatalf("blocked write returned %v, want a server-side statement timeout", err)
	}
	if took := time.Since(started); took >= ritualsSeatActivityTimeout {
		t.Fatalf("the statement timeout took %v", took)
	}
	notStamped("statement timed out", s.alice)
	// Six people's events: the first one's write blocks, the other five
	// queue behind the one drainer.
	quick(users[0])
	time.Sleep(100 * time.Millisecond)
	for _, uid := range users[1:] {
		quick(uid)
	}
	if p, d, _ := state(); p < len(users)-1 || !d {
		t.Fatalf("events did not queue behind the blocked drainer (pending %d, draining %v)", p, d)
	}
	// Every write times out and waits on a retry timer; none lands.
	waitFor(5*time.Second, "retry timer with the queue drained", func() bool {
		p, d, r := state()
		return p == 0 && !d && r >= 1
	})
	notStamped("table lock held", users...)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// The retries stamp every seat with no further events.
	for _, uid := range users {
		ritualsWaitStamped(t, s, uid)
	}
	ritualsWaitDrained(t, gate)
}

// ritualsWaitDrained waits for the gate to go idle: nothing pending, no
// drainer running and no retry timer outstanding, so no goroutine will
// touch the database after the test.
func ritualsWaitDrained(t *testing.T, g *ritualsSeatActivityGate) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		g.mu.Lock()
		busy, pending, retrying := g.draining, len(g.pending), g.retrying
		g.mu.Unlock()
		if !busy && pending == 0 && retrying == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("seat activity still running (%d pending, draining %v, %d retry timers)", pending, busy, retrying)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ritualsWaitStamped waits for the background activity write to stamp uid.
func ritualsWaitStamped(t *testing.T, s *ritualsTestSpace, uid string) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for {
		if ago := ritualsLastActiveAgo(t, s, uid); ago >= 0 && ago <= 30*time.Second {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("seat %s was not stamped (%v ago)", uid, ritualsLastActiveAgo(t, s, uid))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ritualsPairs renders taken pairs sorted, for comparisons.
func ritualsPairs(tries []ritualsSeatTry) string {
	out := make([]string, 0, len(tries))
	for _, tr := range tries {
		out = append(out, tr.userID+"/"+tr.serverID)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// Fix rounds 4 and 5: the in-memory gate and queue in front of the activity
// write.
func TestRitualsSeatActivityGate(t *testing.T) {
	var g ritualsSeatActivityGate
	now := time.Now()
	// The first event starts the drainer; later ones queue behind it.
	if !g.queue("u1", []string{"s1", "s2"}, now) {
		t.Fatal("the first event did not start the drainer")
	}
	if g.queue("u2", []string{"s1"}, now) {
		t.Fatal("a second drainer was started")
	}
	// Inside the throttle a queued pair is not queued again; a new one is.
	g.queue("u1", []string{"s1", "s3"}, now.Add(30*time.Second))
	if got := ritualsPairs(g.take()); got != "u1/s1,u1/s2,u1/s3,u2/s1" {
		t.Fatalf("first take: %s", got)
	}
	// An empty take ends the drain.
	if got := g.take(); got != nil || g.draining {
		t.Fatalf("empty take: %v draining=%v", got, g.draining)
	}
	// A throttled pair neither queues nor starts a drainer.
	if g.queue("u1", []string{"s1"}, now.Add(45*time.Second)) || len(g.pending) != 0 {
		t.Fatalf("a throttled pair was queued (%d pending)", len(g.pending))
	}
	// After the throttle it is due again.
	if !g.queue("u1", []string{"s1"}, now.Add(ritualsSeatActivityThrottle)) {
		t.Fatal("not due after the throttle")
	}
	if got := ritualsPairs(g.take()); got != "u1/s1" {
		t.Fatalf("after the throttle: %s", got)
	}
	// Events during a drain queue without starting another drainer, and
	// the same drainer takes them.
	if g.queue("u2", []string{"s2"}, now) {
		t.Fatal("a second drainer was started mid-drain")
	}
	if got := ritualsPairs(g.take()); got != "u2/s2" {
		t.Fatalf("mid-drain take: %s", got)
	}
	if g.take() != nil {
		t.Fatal("the drain did not end")
	}

	// Fix round 5: a failed write is retried. failed returns the pairs with
	// attempts left and counts one retry timer; requeue puts them back and
	// starts a drainer when none runs; after the last attempt the pair is
	// forgotten, so its next event queues at once.
	var r ritualsSeatActivityGate
	p := ritualsSeatPair{"u1", "s1"}
	r.queue(p.userID, []string{p.serverID}, now)
	retry := r.failed(r.take())
	if len(retry) != 1 || retry[0].failures != 1 || r.retrying != 1 {
		t.Fatalf("first failure: %v, %d timers", retry, r.retrying)
	}
	if r.take() != nil || r.draining {
		t.Fatal("the drain did not end while the retry waits")
	}
	if !r.requeue(retry) || r.retrying != 0 {
		t.Fatalf("the retry did not start a drainer (%d timers)", r.retrying)
	}
	tries := r.take()
	if len(tries) != 1 || tries[0].failures != 1 {
		t.Fatalf("retried take: %v", tries)
	}
	retry = r.failed(tries)
	if len(retry) != 1 || retry[0].failures != 2 {
		t.Fatalf("second failure: %v", retry)
	}
	if r.requeue(retry) {
		t.Fatal("a retry started a second drainer")
	}
	if retry = r.failed(r.take()); len(retry) != 0 || r.retrying != 0 {
		t.Fatalf("retried past %d attempts: %v, %d timers", ritualsSeatActivityAttempts, retry, r.retrying)
	}
	if _, ok := r.seen[p]; ok {
		t.Fatal("an exhausted pair stays throttled")
	}
	if r.queue(p.userID, []string{p.serverID}, now.Add(time.Second)); r.pending[p] != 0 || len(r.pending) != 1 {
		t.Fatalf("an exhausted pair's next event: pending %v", r.pending)
	}
	r.take()
	r.take()
	// A retry meets a fresh event for the same pair: one entry, and the
	// failures so far are kept.
	r.queue(p.userID, []string{p.serverID}, now.Add(time.Minute+time.Second))
	retry = r.failed(r.take())
	r.take()
	r.queue(p.userID, []string{p.serverID}, now.Add(3*time.Minute))
	r.requeue(retry)
	if len(r.pending) != 1 || r.pending[p] != 1 || r.retrying != 0 {
		t.Fatalf("retry merge: pending %v, %d timers", r.pending, r.retrying)
	}
	r.take()
	r.take()

	// The queue is bounded: past ritualsSeatActivityMemo an event is dropped
	// and not remembered, so its next event queues it.
	ids := make([]string, ritualsSeatActivityMemo+1)
	for i := range ids {
		ids[i] = strconv.Itoa(i)
	}
	g.queue("w", ids, now)
	last := ritualsSeatPair{"w", ids[len(ids)-1]}
	if _, ok := g.seen[last]; len(g.pending) != ritualsSeatActivityMemo || ok {
		t.Fatalf("pending %d, dropped pair remembered %v", len(g.pending), ok)
	}
	// A retry that finds the queue full is dropped and forgotten too.
	g.seen[p] = now
	g.retrying = 1
	if g.requeue([]ritualsSeatTry{{p, 1}}); len(g.pending) != ritualsSeatActivityMemo || g.retrying != 0 {
		t.Fatalf("a retry overfilled the queue (pending %d, %d timers)", len(g.pending), g.retrying)
	}
	if _, ok := g.seen[p]; ok {
		t.Fatal("a retry dropped from a full queue stays throttled")
	}
	if n := len(g.take()); n != ritualsSeatActivityMemo {
		t.Fatalf("took %d", n)
	}
	g.queue("w", []string{last.serverID}, now)
	if got := ritualsPairs(g.take()); got != "w/"+last.serverID {
		t.Fatalf("the dropped pair's next event: %s", got)
	}
	g.take()
	// The memory is bounded: when full it starts over.
	var m ritualsSeatActivityGate
	for i := 0; len(m.seen) < ritualsSeatActivityMemo; i++ {
		m.queue("m", []string{strconv.Itoa(i)}, now)
		m.take()
	}
	m.queue("m", []string{"one-more"}, now)
	if len(m.seen) != 1 {
		t.Fatalf("memo size after overflow = %d, want 1", len(m.seen))
	}
	// Fix round 5: valid ids come back canonical, invalid ones are dropped.
	const id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	got := ritualsValidUUIDs([]string{strings.ToUpper(id), "{" + id + "}", "urn:uuid:" + id, "not-a-uuid", ""})
	if strings.Join(got, ",") != id+","+id+","+id {
		t.Fatalf("ritualsValidUUIDs = %v", got)
	}
}

// Fix round 3: a fresh device sign-in is never hidden behind an older
// last_active_at stamp (the ranking takes the latest of all four signals).
func TestRitualsDeviceCapFreshSignInBeatsStaleStampDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool) // alice (subA, owner) and bob (subB)
	hub := &ritualsRecordingHub{connected: map[string]bool{}}
	s.rt.hub = hub
	s.rt.personSecret = ritualsPersonKeySecret("synthetic-jwt-secret-for-tests-only")
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	devices := ritualsFiveDevices(t, s)
	alice, signedIn, d2, d3, idle := devices[0], devices[1], devices[2], devices[3], devices[4]
	ritualsSeatTimes(t, s, alice, 50*time.Minute, 5*time.Minute)
	// Stamped three hours ago, but its device signed in a minute ago.
	ritualsSeatTimes(t, s, signedIn, 3*time.Hour, 3*time.Hour)
	if _, err := pool.Exec(ctx, `INSERT INTO device_keys (user_id, device_id, device_public_key, last_seen)
		VALUES ($1, 'k1', '\x00', now() - interval '1 minute')`, signedIn); err != nil {
		t.Fatal(err)
	}
	ritualsSeatTimes(t, s, d2, 30*time.Minute, 30*time.Minute)
	ritualsSeatTimes(t, s, d3, 20*time.Minute, 20*time.Minute)
	ritualsSeatTimes(t, s, idle, 2*time.Hour, 2*time.Hour)

	res := ritualsClaimRetires(t, s, s.user(t), s.subA)
	if len(res.retired) != 1 || res.retired[0] != idle {
		t.Fatalf("retired %v, want the idle seat %s (not %s, signed in a minute ago)", res.retired, idle, signedIn)
	}
}

// Fix round 2: a seat without its MLS credential or member row is only
// "never finished joining" once it is older than ritualsSeatJoinGrace; a
// device still registering ranks as an ordinary unconnected seat.
func TestRitualsDeviceCapJoinGraceDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	s := newRitualsTestSpace(t, pool) // alice (subA, owner) and bob (subB)
	hub := &ritualsRecordingHub{connected: map[string]bool{}}
	s.rt.hub = hub
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	devices := []string{s.alice}
	for i := 0; i < 4; i++ {
		uid := s.user(t)
		s.claim(t, uid, s.subA, "member")
		devices = append(devices, uid)
	}
	alice, d1, joining := devices[0], devices[1], devices[4]
	for i, uid := range devices {
		ritualsSeatAge(t, s, uid, time.Duration(50-i*10)*time.Minute)
		if uid != joining {
			s.device(t, uid, "dev-"+uid[:8])
		}
	}
	// The newest device claimed 30 s ago and has not uploaded its MLS
	// credential yet; the laptop is online.
	ritualsSeatAge(t, s, joining, 30*time.Second)
	hub.connected[alice] = true

	res := ritualsClaimRetires(t, s, s.user(t), s.subA)
	if len(res.retired) != 1 || res.retired[0] != d1 {
		t.Fatalf("retired %v, want the least recently active %s, not the joining %s", res.retired, d1, joining)
	}

	// Past the grace without a credential it is unfinished and goes first,
	// although it is the most recently active unconnected seat.
	ritualsSeatTimes(t, s, joining, ritualsSeatJoinGrace+time.Minute, 0)
	res = ritualsClaimRetires(t, s, s.user(t), s.subA)
	if len(res.retired) != 1 || res.retired[0] != joining {
		t.Fatalf("retired %v, want the unfinished %s", res.retired, joining)
	}
}

// Fix round 2 schema: last_active_at is added by the Rituals ensure list,
// nullable with no default, so a database from before it (or rows a
// previous release inserts) keep NULL; NULL ranks by the older recency
// (creation / device sign-in), and the statement is idempotent.
func TestRitualsSeatLastActiveColumnDB(t *testing.T) {
	pool, cleanup := db.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newRitualsTestSpace(t, pool) // alice (subA, owner) and bob (subB)
	hub := &ritualsRecordingHub{connected: map[string]bool{}}
	s.rt.hub = hub
	ritualsCurrent.Store(s.rt)
	defer ritualsCurrent.Store(nil)

	// The schema before this change: no column. Restore it whatever happens
	// (deferred after cleanup, so it runs before the pool closes).
	defer func() {
		if err := RitualsBootstrap(context.Background(), pool); err != nil {
			t.Errorf("restore schema: %v", err)
		}
	}()
	if _, err := pool.Exec(ctx, `ALTER TABLE rituals.seats DROP COLUMN last_active_at`); err != nil {
		t.Fatal(err)
	}
	// The previous release's seat insert, verbatim, works on both schemas.
	oldInsert := `INSERT INTO rituals.seats (sp, sub, user_id) VALUES ($1, $2, $3)`
	before := s.user(t)
	if _, err := pool.Exec(ctx, oldInsert, s.sp, s.subA, before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := RitualsBootstrap(ctx, pool); err != nil {
			t.Fatalf("bootstrap %d: %v", i, err)
		}
	}
	var dataType, nullable string
	var def *string
	if err := pool.QueryRow(ctx, `
		SELECT data_type, is_nullable, column_default FROM information_schema.columns
		WHERE table_schema = 'rituals' AND table_name = 'seats' AND column_name = 'last_active_at'`).
		Scan(&dataType, &nullable, &def); err != nil {
		t.Fatal(err)
	}
	if dataType != "timestamp with time zone" || nullable != "YES" || def != nil {
		t.Fatalf("column = %s nullable %s default %v", dataType, nullable, def)
	}
	var stamped int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM rituals.seats WHERE sp = $1 AND last_active_at IS NOT NULL`, s.sp).Scan(&stamped); err != nil || stamped != 0 {
		t.Fatalf("pre-existing seats got a value: %d %v", stamped, err)
	}
	after := s.user(t)
	if _, err := pool.Exec(ctx, oldInsert, s.sp, s.subA, after); err != nil {
		t.Fatalf("previous release insert on the new schema: %v", err)
	}
	if ritualsLastActiveAgo(t, s, after) != -1 {
		t.Fatal("previous release insert got a last_active_at")
	}
	// A recorded value survives a restart (the ensure list is idempotent).
	ritualsSeatAge(t, s, s.alice, 5*time.Minute)
	if err := RitualsBootstrap(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if ago := ritualsLastActiveAgo(t, s, s.alice); ago < 4*time.Minute || ago > 6*time.Minute {
		t.Fatalf("restart changed last_active_at (%v ago)", ago)
	}

	// Ranking with NULLs: alice (recorded 5 min ago), before/after (NULL),
	// plus two more NULL seats; NULL falls back to the latest of creation and
	// device sign-in. Everyone has a credential, nobody is connected.
	more := []string{s.user(t), s.user(t)}
	for _, uid := range more {
		if _, err := pool.Exec(ctx, oldInsert, s.sp, s.subA, uid); err != nil {
			t.Fatal(err)
		}
	}
	for _, uid := range append([]string{s.alice, before, after}, more...) {
		s.device(t, uid, "dev-"+uid[:8])
		if _, err := pool.Exec(ctx, `INSERT INTO server_members (server_id, user_id, permission_level) VALUES ($1, $2, 0)
			ON CONFLICT DO NOTHING`, s.serverID, uid); err != nil {
			t.Fatal(err)
		}
	}
	setCreated := func(uid string, ago time.Duration) {
		if _, err := pool.Exec(ctx, `UPDATE rituals.seats SET created_at = now() - make_interval(secs => $3)
			WHERE sp = $1 AND user_id = $2`, s.sp, uid, ago.Seconds()); err != nil {
			t.Fatal(err)
		}
	}
	setCreated(before, 3*time.Hour) // oldest seat, but signed in just now
	setCreated(after, 2*time.Hour)  // the stalest by the fallback
	setCreated(more[0], time.Hour)
	setCreated(more[1], time.Hour)
	if _, err := pool.Exec(ctx, `INSERT INTO device_keys (user_id, device_id, device_public_key, last_seen)
		VALUES ($1, 'k1', '\x00', now())`, before); err != nil {
		t.Fatal(err)
	}
	if got := len(ritualsSeatsOf(t, s, s.subA)); got != ritualsSeatsPerPerson {
		t.Fatalf("setup seats = %d", got)
	}
	res := ritualsClaimRetires(t, s, s.user(t), s.subA)
	if len(res.retired) != 1 || res.retired[0] != after {
		t.Fatalf("retired %v, want %s (NULL ranks by creation / sign-in)", res.retired, after)
	}
}
