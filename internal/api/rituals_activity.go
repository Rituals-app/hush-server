package api

// Rituals fork: device seat activity (rituals.seats.last_active_at) from the
// WebSocket hub. The hub calls the hook on a connection's own goroutine (its
// read pump, or Run's deferred Unregister), so the hook never touches the
// database there: an in-memory gate admits each (user, server) pair at most
// once per ritualsSeatActivityThrottle into a bounded queue, and one
// background drainer at a time writes the queue in batches.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// ritualsSeatActivityThrottle: a WebSocket subscribe, unsubscribe or
	// disconnect queues a (user, server) pair at most once per interval
	// (ritualsSeatActivityGate), and the UPDATE itself only rewrites a value
	// older than this (touchSeatActivityPairs), so a reconnecting tab costs at
	// most one row write per seat per interval.
	ritualsSeatActivityThrottle = 60 * time.Second
	// ritualsSeatActivityTimeout bounds one batch write.
	ritualsSeatActivityTimeout = 2 * time.Second
	// ritualsSeatActivityBatch is the most pairs one UPDATE writes.
	ritualsSeatActivityBatch = 512
	// ritualsSeatActivityMemo bounds both the gate's memory of queued pairs
	// and the queue itself. When the memory is full it starts over (a
	// forgotten pair only costs one more UPDATE, which the SQL throttle turns
	// into a no-op inside the interval); when the queue is full an event is
	// dropped without being remembered, so the pair's next event retries it.
	ritualsSeatActivityMemo = 8192
)

// ritualsSeatPair is one (Hush user, Space server) activity stamp.
type ritualsSeatPair struct{ userID, serverID string }

// ritualsSeatActivityGate decides, without I/O, which activity events reach
// the database, and holds them until the drainer takes them. At most one
// drainer runs at a time. The zero value is ready to use.
type ritualsSeatActivityGate struct {
	mu       sync.Mutex
	seen     map[ritualsSeatPair]time.Time // pair -> last queued
	pending  map[ritualsSeatPair]struct{}
	draining bool
}

// queue records the pairs of userID due for a write at now. It reports
// whether the caller must start the drainer (none is running and something
// is pending); then the caller owns the drain until take returns nil.
func (g *ritualsSeatActivityGate) queue(userID string, serverIDs []string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, id := range serverIDs {
		p := ritualsSeatPair{userID, id}
		if last, ok := g.seen[p]; ok && now.Sub(last) < ritualsSeatActivityThrottle {
			continue
		}
		if len(g.pending) >= ritualsSeatActivityMemo {
			break
		}
		if g.seen == nil || len(g.seen) >= ritualsSeatActivityMemo {
			g.seen = make(map[ritualsSeatPair]time.Time)
		}
		if g.pending == nil {
			g.pending = make(map[ritualsSeatPair]struct{})
		}
		g.seen[p] = now
		g.pending[p] = struct{}{}
	}
	if g.draining || len(g.pending) == 0 {
		return false
	}
	g.draining = true
	return true
}

// take hands the drainer every pending pair, or ends the drain and returns
// nil when nothing is pending.
func (g *ritualsSeatActivityGate) take() []ritualsSeatPair {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.pending) == 0 {
		g.draining = false
		return nil
	}
	out := make([]ritualsSeatPair, 0, len(g.pending))
	for p := range g.pending {
		out = append(out, p)
	}
	g.pending = nil
	return out
}

// forget drops the memory of pairs whose write failed, so the next event of
// each is queued again at once instead of a throttle interval later.
func (g *ritualsSeatActivityGate) forget(pairs []ritualsSeatPair) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, p := range pairs {
		delete(g.seen, p)
	}
}

// noteSeatActivity is the hub's server activity hook (EnableRituals): a
// connection of userID subscribed to, unsubscribed from or disconnected from
// serverIDs. It returns at once; the gate queues what is due and a single
// background drainer writes it (drainSeatActivity).
func (rt *ritualsRuntime) noteSeatActivity(userID string, serverIDs []string) {
	if rt.pool == nil {
		return
	}
	if _, err := uuid.Parse(userID); err != nil {
		return
	}
	if rt.seatActivity.queue(userID, ritualsValidUUIDs(serverIDs), time.Now()) {
		go rt.drainSeatActivity()
	}
}

// drainSeatActivity writes queued pairs until the queue is empty, one batch
// at a time, each bounded by ritualsSeatActivityTimeout. A failed batch is
// logged and forgotten by the gate so its pairs' next events retry it.
func (rt *ritualsRuntime) drainSeatActivity() {
	for {
		pairs := rt.seatActivity.take()
		if pairs == nil {
			return
		}
		for start := 0; start < len(pairs); start += ritualsSeatActivityBatch {
			batch := pairs[start:min(start+ritualsSeatActivityBatch, len(pairs))]
			ctx, cancel := context.WithTimeout(context.Background(), ritualsSeatActivityTimeout)
			err := rt.touchSeatActivityPairs(ctx, batch)
			cancel()
			if err != nil {
				slog.Warn("rituals: seat activity", "err", err, "pairs", len(batch))
				rt.seatActivity.forget(batch)
			}
		}
	}
}

// touchSeatActivity stamps last_active_at on userID's seats in the spaces of
// serverIDs (see touchSeatActivityPairs). Best effort: an error is logged,
// never returned. WebSocket paths go through noteSeatActivity instead.
func (rt *ritualsRuntime) touchSeatActivity(ctx context.Context, userID string, serverIDs []string) {
	if _, err := uuid.Parse(userID); err != nil {
		return
	}
	ids := ritualsValidUUIDs(serverIDs)
	pairs := make([]ritualsSeatPair, 0, len(ids))
	for _, id := range ids {
		pairs = append(pairs, ritualsSeatPair{userID, id})
	}
	if err := rt.touchSeatActivityPairs(ctx, pairs); err != nil {
		slog.Warn("rituals: seat activity", "err", err)
	}
}

// touchSeatActivityPairs stamps last_active_at on each pair's seat (the
// user's seat in the space of the server) in one UPDATE, only where the
// stored value is NULL or older than ritualsSeatActivityThrottle. Pairs that
// are not two UUIDs are skipped.
func (rt *ritualsRuntime) touchSeatActivityPairs(ctx context.Context, pairs []ritualsSeatPair) error {
	if rt.pool == nil {
		return nil
	}
	users := make([]string, 0, len(pairs))
	servers := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if _, err := uuid.Parse(p.userID); err != nil {
			continue
		}
		if _, err := uuid.Parse(p.serverID); err != nil {
			continue
		}
		users = append(users, p.userID)
		servers = append(servers, p.serverID)
	}
	if len(users) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, ritualsSeatActivityTimeout)
	defer cancel()
	_, err := rt.pool.Exec(ctx, `
		UPDATE rituals.seats s SET last_active_at = now()
		FROM rituals.spaces sp, unnest($1::uuid[], $2::uuid[]) AS a(user_id, server_id)
		WHERE sp.server_id = a.server_id
		  AND s.sp = sp.sp
		  AND s.user_id = a.user_id
		  AND (s.last_active_at IS NULL OR s.last_active_at < now() - make_interval(secs => $3))`,
		users, servers, ritualsSeatActivityThrottle.Seconds())
	return err
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
