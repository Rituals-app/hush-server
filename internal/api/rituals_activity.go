package api

// Rituals fork: device seat activity (rituals.seats.last_active_at) from the
// WebSocket hub. The hub calls the hook on a connection's own goroutine (its
// read pump, or Run's deferred Unregister), so the hook never touches the
// database there: an in-memory gate admits each (user, server) pair at most
// once per ritualsSeatActivityThrottle and at most ritualsSeatActivityWorkers
// writes at a time, and the admitted write runs in the background.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// ritualsSeatActivityThrottle: a WebSocket subscribe, unsubscribe or
	// disconnect stamps rituals.seats.last_active_at at most once per
	// (user, server) per interval in memory (ritualsSeatActivityGate), and the
	// UPDATE itself only rewrites a value older than this (touchSeatActivity),
	// so a reconnecting tab costs at most one row write per seat per interval.
	ritualsSeatActivityThrottle = 60 * time.Second
	// ritualsSeatActivityTimeout bounds one best-effort activity write.
	ritualsSeatActivityTimeout = 2 * time.Second
	// ritualsSeatActivityWorkers is the most activity writes in flight; an
	// event over it is dropped without being remembered, so the next
	// subscribe, unsubscribe or disconnect of that pair retries it.
	ritualsSeatActivityWorkers = 4
	// ritualsSeatActivityMemo bounds the gate's memory of admitted pairs.
	// When full it starts over: a forgotten pair only costs one more UPDATE,
	// which the SQL throttle turns into a no-op inside the interval.
	ritualsSeatActivityMemo = 8192
)

// ritualsSeatActivityGate decides, without I/O, which activity events reach
// the database. The zero value is ready to use.
type ritualsSeatActivityGate struct {
	mu       sync.Mutex
	seen     map[string]time.Time // userID + "/" + serverID -> last admitted
	inFlight int
}

// admit returns the serverIDs of userID due for a write at now and reserves
// a worker for them, or nil when none is due or every worker is busy (then
// nothing is remembered). A non-nil result must be followed by release.
func (g *ritualsSeatActivityGate) admit(userID string, serverIDs []string, now time.Time) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inFlight >= ritualsSeatActivityWorkers {
		return nil
	}
	var due []string
	for _, id := range serverIDs {
		if last, ok := g.seen[userID+"/"+id]; ok && now.Sub(last) < ritualsSeatActivityThrottle {
			continue
		}
		due = append(due, id)
	}
	if len(due) == 0 {
		return nil
	}
	if g.seen == nil || len(g.seen)+len(due) > ritualsSeatActivityMemo {
		g.seen = make(map[string]time.Time)
	}
	for _, id := range due {
		g.seen[userID+"/"+id] = now
	}
	g.inFlight++
	return due
}

// release frees the worker an admit reserved.
func (g *ritualsSeatActivityGate) release() {
	g.mu.Lock()
	g.inFlight--
	g.mu.Unlock()
}

// noteSeatActivity is the hub's server activity hook (EnableRituals): a
// connection of userID subscribed to, unsubscribed from or disconnected from
// serverIDs. It returns at once: what the gate admits is written by a
// background goroutine (touchSeatActivity), bounded by
// ritualsSeatActivityTimeout; the rest is dropped.
func (rt *ritualsRuntime) noteSeatActivity(userID string, serverIDs []string) {
	if rt.pool == nil {
		return
	}
	if _, err := uuid.Parse(userID); err != nil {
		return
	}
	due := rt.seatActivity.admit(userID, ritualsValidUUIDs(serverIDs), time.Now())
	if len(due) == 0 {
		return
	}
	go func() {
		defer rt.seatActivity.release()
		ctx, cancel := context.WithTimeout(context.Background(), ritualsSeatActivityTimeout)
		defer cancel()
		rt.touchSeatActivity(ctx, userID, due)
	}()
}

// touchSeatActivity stamps last_active_at on userID's seats in the spaces of
// serverIDs, only where the stored value is NULL or older than
// ritualsSeatActivityThrottle. Best effort: an error is logged, never
// returned. Callers on a WebSocket path go through noteSeatActivity.
func (rt *ritualsRuntime) touchSeatActivity(ctx context.Context, userID string, serverIDs []string) {
	if _, err := uuid.Parse(userID); err != nil {
		return
	}
	ids := ritualsValidUUIDs(serverIDs)
	if len(ids) == 0 || rt.pool == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, ritualsSeatActivityTimeout)
	defer cancel()
	if _, err := rt.pool.Exec(ctx, `
		UPDATE rituals.seats s SET last_active_at = now()
		FROM rituals.spaces sp
		WHERE sp.server_id = ANY($2::uuid[])
		  AND s.sp = sp.sp
		  AND s.user_id = $1
		  AND (s.last_active_at IS NULL OR s.last_active_at < now() - make_interval(secs => $3))`,
		userID, ids, ritualsSeatActivityThrottle.Seconds()); err != nil {
		slog.Warn("rituals: seat activity", "err", err)
	}
}

// ritualsValidUUIDs keeps the ids that parse as UUIDs.
func ritualsValidUUIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := uuid.Parse(id); err == nil {
			out = append(out, id)
		}
	}
	return out
}
