package api

// Rituals fork: device seat activity (rituals.seats.last_active_at) from the
// WebSocket hub. The hub calls the hook on a connection's own goroutine (its
// read pump, or Run's deferred Unregister), so the hook never touches the
// database there: an in-memory gate admits each (user, server) pair at most
// once per ritualsSeatActivityThrottle into a bounded queue, and one
// background drainer at a time writes the queue in batches. A failed write,
// and a seat row skipped because another transaction held it, are retried a
// bounded number of times.

import (
	"context"
	"log/slog"
	"strconv"
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
	// ritualsSeatActivityTimeout bounds one batch write on the client.
	ritualsSeatActivityTimeout = 2 * time.Second
	// ritualsSeatActivityStatementTimeout is the batch's statement_timeout on
	// the server, below the client bound. pgx drops the connection when a
	// context ends but does not cancel the statement, so without it a write
	// that timed out here could keep waiting (and land) on the server.
	ritualsSeatActivityStatementTimeout = 1500 * time.Millisecond
	// ritualsSeatActivityBatch is the most pairs one UPDATE writes.
	ritualsSeatActivityBatch = 512
	// ritualsSeatActivityMemo bounds both the gate's memory of queued pairs
	// and the queue itself. When the memory is full it starts over (a
	// forgotten pair only costs one more UPDATE, which the SQL throttle turns
	// into a no-op inside the interval); when the queue is full an event is
	// dropped without being remembered, so the pair's next event retries it.
	ritualsSeatActivityMemo = 8192
	// ritualsSeatActivityAttempts: a pair whose write fails, or whose seat
	// row was skipped as locked, is queued again after
	// ritualsSeatActivityRetryDelay, for at most this many writes in all;
	// then the gate forgets it, so its next event retries it. A disconnect is
	// a session's last event, so without the retry one failed or skipped
	// write would leave the seat at its subscribe time.
	ritualsSeatActivityAttempts   = 3
	ritualsSeatActivityRetryDelay = 10 * time.Second
)

// ritualsSeatPair is one (Hush user, Space server) activity stamp, both ids
// in canonical UUID form (ritualsValidUUIDs).
type ritualsSeatPair struct{ userID, serverID string }

// ritualsSeatTry is a queued pair and how many of its writes have failed.
type ritualsSeatTry struct {
	ritualsSeatPair
	failures int
}

// ritualsSeatActivityGate decides, without I/O, which activity events reach
// the database, and holds them until the drainer takes them. At most one
// drainer runs at a time. The zero value is ready to use.
type ritualsSeatActivityGate struct {
	mu       sync.Mutex
	seen     map[ritualsSeatPair]time.Time // pair -> last queued
	pending  map[ritualsSeatPair]int       // pair -> failed writes so far
	draining bool
	retrying int // retry timers not yet fired

	retryDelay time.Duration // 0: ritualsSeatActivityRetryDelay (tests shorten it)
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
		if _, ok := g.pending[p]; ok {
			continue // queued, or queued again by a retry, and not yet taken
		}
		if len(g.pending) >= ritualsSeatActivityMemo {
			break
		}
		if g.seen == nil || len(g.seen) >= ritualsSeatActivityMemo {
			g.seen = make(map[ritualsSeatPair]time.Time)
		}
		if g.pending == nil {
			g.pending = make(map[ritualsSeatPair]int)
		}
		g.seen[p] = now
		g.pending[p] = 0
	}
	return g.claimDrainLocked()
}

// claimDrainLocked makes the caller the drainer when none runs and something
// is pending. g.mu must be held.
func (g *ritualsSeatActivityGate) claimDrainLocked() bool {
	if g.draining || len(g.pending) == 0 {
		return false
	}
	g.draining = true
	return true
}

// take hands the drainer every pending pair, or ends the drain and returns
// nil when nothing is pending.
func (g *ritualsSeatActivityGate) take() []ritualsSeatTry {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.pending) == 0 {
		g.draining = false
		return nil
	}
	out := make([]ritualsSeatTry, 0, len(g.pending))
	for p, n := range g.pending {
		out = append(out, ritualsSeatTry{p, n})
	}
	g.pending = nil
	return out
}

// failed records a failed write of tries. It returns the ones to retry
// (with their failure counts) and counts one retry timer the caller must
// start; the others have used every attempt and are forgotten, so their
// next event retries them at once instead of a throttle interval later.
func (g *ritualsSeatActivityGate) failed(tries []ritualsSeatTry) []ritualsSeatTry {
	g.mu.Lock()
	defer g.mu.Unlock()
	var retry []ritualsSeatTry
	for _, tr := range tries {
		tr.failures++
		if tr.failures < ritualsSeatActivityAttempts {
			retry = append(retry, tr)
		} else {
			delete(g.seen, tr.ritualsSeatPair)
		}
	}
	if len(retry) > 0 {
		g.retrying++
	}
	return retry
}

// requeue puts retries back in the queue when their timer fires, and reports
// whether the caller must start the drainer (as queue does). A retry that
// finds the queue full is dropped and forgotten, like a new event would be.
func (g *ritualsSeatActivityGate) requeue(tries []ritualsSeatTry) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.retrying--
	for _, tr := range tries {
		if n, ok := g.pending[tr.ritualsSeatPair]; ok {
			g.pending[tr.ritualsSeatPair] = max(n, tr.failures)
			continue
		}
		if len(g.pending) >= ritualsSeatActivityMemo {
			delete(g.seen, tr.ritualsSeatPair)
			continue
		}
		if g.pending == nil {
			g.pending = make(map[ritualsSeatPair]int)
		}
		g.pending[tr.ritualsSeatPair] = tr.failures
	}
	return g.claimDrainLocked()
}

// delay is the wait before a failed write is retried.
func (g *ritualsSeatActivityGate) delay() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.retryDelay > 0 {
		return g.retryDelay
	}
	return ritualsSeatActivityRetryDelay
}

// noteSeatActivity is the hub's server activity hook (EnableRituals): a
// connection of userID subscribed to, unsubscribed from or disconnected from
// serverIDs. It returns at once; the gate queues what is due and a single
// background drainer writes it (drainSeatActivity). Ids are canonicalised
// first, so another spelling of one id (upper case, braces) shares its
// throttle.
func (rt *ritualsRuntime) noteSeatActivity(userID string, serverIDs []string) {
	if rt.pool == nil {
		return
	}
	u, err := uuid.Parse(userID)
	if err != nil {
		return
	}
	if rt.seatActivity.queue(u.String(), ritualsValidUUIDs(serverIDs), time.Now()) {
		go rt.drainSeatActivity()
	}
}

// drainSeatActivity writes queued pairs until the queue is empty, one batch
// at a time, each bounded by ritualsSeatActivityTimeout. A failed batch is
// logged and retried after the gate's delay, and so are the pairs whose seat
// row was skipped as locked; each pair gets at most
// ritualsSeatActivityAttempts writes.
func (rt *ritualsRuntime) drainSeatActivity() {
	g := &rt.seatActivity
	for {
		tries := g.take()
		if tries == nil {
			return
		}
		for start := 0; start < len(tries); start += ritualsSeatActivityBatch {
			batch := tries[start:min(start+ritualsSeatActivityBatch, len(tries))]
			pairs := make([]ritualsSeatPair, len(batch))
			for i, tr := range batch {
				pairs[i] = tr.ritualsSeatPair
			}
			skipped, err := rt.touchSeatActivityPairs(context.Background(), pairs)
			var retry []ritualsSeatTry
			switch {
			case err != nil:
				retry = g.failed(batch)
				slog.Warn("rituals: seat activity", "err", err, "pairs", len(batch), "retrying", len(retry))
			case len(skipped) > 0:
				// Rows another transaction held: retried like a failed
				// write, in case that transaction rolls back unstamped.
				held := ritualsSeatTriesFor(batch, skipped)
				retry = g.failed(held)
				if n := len(held) - len(retry); n > 0 {
					slog.Warn("rituals: seat activity: locked seats left unstamped", "pairs", n)
				}
			}
			if len(retry) > 0 {
				time.AfterFunc(g.delay(), func() {
					if g.requeue(retry) {
						rt.drainSeatActivity()
					}
				})
			}
		}
	}
}

// touchSeatActivity stamps last_active_at on userID's seats in the spaces of
// serverIDs (see touchSeatActivityPairs). Best effort: an error is logged,
// never returned. WebSocket paths go through noteSeatActivity instead.
func (rt *ritualsRuntime) touchSeatActivity(ctx context.Context, userID string, serverIDs []string) {
	u, err := uuid.Parse(userID)
	if err != nil {
		return
	}
	ids := ritualsValidUUIDs(serverIDs)
	pairs := make([]ritualsSeatPair, 0, len(ids))
	for _, id := range ids {
		pairs = append(pairs, ritualsSeatPair{u.String(), id})
	}
	if _, err := rt.touchSeatActivityPairs(ctx, pairs); err != nil {
		slog.Warn("rituals: seat activity", "err", err)
	}
}

// touchSeatActivityPairs stamps last_active_at on each pair's seat (the
// user's seat in the space of the server) in one UPDATE, only where the
// stored value is NULL or older than ritualsSeatActivityThrottle. Pairs that
// are not two UUIDs are skipped.
//
// A seat row another transaction holds is skipped, not waited on (SKIP
// LOCKED): its holder is a claim, which stamps the seat itself, or a delete
// (the device cap or a sync). So one busy row never stalls the batch, and
// the write never waits on a lock held by a statement that could be waiting
// on it, which rules out deadlocks with those multi-row deletes. The pairs
// of the due rows it did not stamp (skipped as locked, or changed since the
// statement's snapshot) are returned, so the caller can try them again: the
// holder may roll back without stamping, and a retry of a row the holder
// stamped or deleted is a no-op. The transaction's statement_timeout ends a
// write blocked any other way (a table lock) on the server too.
func (rt *ritualsRuntime) touchSeatActivityPairs(ctx context.Context, pairs []ritualsSeatPair) ([]ritualsSeatPair, error) {
	if rt.pool == nil {
		return nil, nil
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
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, ritualsSeatActivityTimeout)
	defer cancel()
	tx, err := rt.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`,
		strconv.FormatInt(ritualsSeatActivityStatementTimeout.Milliseconds(), 10)); err != nil {
		return nil, err
	}
	// cand: the due rows as the snapshot sees them, unlocked. due: those this
	// statement locked (the lock rechecks the throttle on the newest row
	// version). cand rows missing from due were not stamped.
	rows, err := tx.Query(ctx, `
		WITH act AS (
			SELECT * FROM unnest($1::uuid[], $2::uuid[]) AS a(user_id, server_id)
		), cand AS (
			SELECT s.sp, s.user_id, act.server_id
			FROM rituals.seats s
			JOIN rituals.spaces sp ON sp.sp = s.sp
			JOIN act ON act.server_id = sp.server_id AND act.user_id = s.user_id
			WHERE s.last_active_at IS NULL OR s.last_active_at < now() - make_interval(secs => $3)
		), due AS (
			SELECT s.sp, s.user_id
			FROM rituals.seats s
			JOIN rituals.spaces sp ON sp.sp = s.sp
			JOIN act ON act.server_id = sp.server_id AND act.user_id = s.user_id
			WHERE s.last_active_at IS NULL OR s.last_active_at < now() - make_interval(secs => $3)
			ORDER BY s.sp, s.user_id
			FOR NO KEY UPDATE OF s SKIP LOCKED
		), stamped AS (
			UPDATE rituals.seats s SET last_active_at = now()
			FROM due
			WHERE s.sp = due.sp AND s.user_id = due.user_id
		)
		SELECT cand.user_id::text, cand.server_id::text
		FROM cand
		WHERE NOT EXISTS (SELECT 1 FROM due WHERE due.sp = cand.sp AND due.user_id = cand.user_id)`,
		users, servers, ritualsSeatActivityThrottle.Seconds())
	if err != nil {
		return nil, err
	}
	var skipped []ritualsSeatPair
	for rows.Next() {
		var p ritualsSeatPair
		if err := rows.Scan(&p.userID, &p.serverID); err != nil {
			rows.Close()
			return nil, err
		}
		skipped = append(skipped, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return skipped, nil
}

// ritualsSeatTriesFor returns the tries of batch whose pair is in pairs.
func ritualsSeatTriesFor(batch []ritualsSeatTry, pairs []ritualsSeatPair) []ritualsSeatTry {
	want := make(map[ritualsSeatPair]struct{}, len(pairs))
	for _, p := range pairs {
		want[p] = struct{}{}
	}
	out := make([]ritualsSeatTry, 0, len(pairs))
	for _, tr := range batch {
		if _, ok := want[tr.ritualsSeatPair]; ok {
			out = append(out, tr)
		}
	}
	return out
}

// ritualsValidUUIDs keeps the ids that parse as UUIDs, in canonical form
// (lower case, no braces or urn prefix), so one id has one gate key.
func ritualsValidUUIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if u, err := uuid.Parse(id); err == nil {
			out = append(out, u.String())
		}
	}
	return out
}
