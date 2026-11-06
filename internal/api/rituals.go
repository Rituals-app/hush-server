package api

// Rituals Spaces (modified by Rituals, 2026-11-05; AGPL-3.0 section 5(a)).
//
// One Hush guild ("space") per shared Rituals task. Rituals never holds,
// derives or sees Hush keys: it only signs short-lived tickets ("this Rituals
// person may enter this space") and membership syncs with an Ed25519 key.
// This server holds the public half (RITUALS_TICKET_PUBLIC_KEY) and keeps its
// own state in the `rituals` Postgres schema, created idempotently at startup
// instead of as a numbered migration so upstream migrations stay untouched.
//
// Files:
//   rituals.go         runtime, config, startup bootstrap, routes
//   rituals_ticket.go  rt1 ticket / rts1 sync / rtf1 fresh verification
//   rituals_spaces.go  POST /api/rituals/spaces/claim and /sync
//   rituals_fresh.go   POST /api/rituals/spaces/fresh (content-free new flag)
//   rituals_peek.go    POST /api/rituals/spaces/peek (seat hints before register)
//   rituals_guard.go   small hooks called from upstream handlers
//   rituals_realip.go  client IP behind the Caddy edge
//
// Every hook is a no-op unless RITUALS_MODE=1 enabled the runtime, so the
// upstream behaviour (and its unit tests) are unchanged outside Rituals mode.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hushhq/hush-server/internal/db"
	"github.com/hushhq/hush-server/internal/livekit"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"
)

// RitualsHub is the WebSocket hub surface the Rituals routes use.
// *ws.Hub satisfies it.
type RitualsHub interface {
	GlobalBroadcaster
	Broadcast(channelID string, message []byte, excludeClientID string)
	// DisconnectUserFromServer drops a removed member from one server and
	// its channels without closing sockets (wire contract Item 3, D18).
	// A non-empty reason goes into the direct member_kicked frame.
	DisconnectUserFromServer(userID, serverID string, channelIDs []string, reason string)
	// SetSubscribeHook installs the per-subscribe replay of pending MLS
	// remove requests (wire contract Item 2, D15).
	SetSubscribeHook(fn func(ctx context.Context, channelID, userID string) [][]byte)
	// ConnectedUsers reports which users have a live WebSocket connection;
	// the device seat cap never retires those first (retireOldSeats). Read
	// lock only, no I/O: safe inside the claim transaction.
	ConnectedUsers(userIDs []string) map[string]bool
	// SetServerActivityHook installs the per-connection server activity
	// callback (subscribe, unsubscribe, disconnect), called on the
	// connection's goroutine outside the hub lock, so it must not block;
	// Rituals keeps rituals.seats.last_active_at with it (rituals_activity.go).
	SetServerActivityHook(fn func(userID string, serverIDs []string))
}

// RitualsOptions wires the Rituals Spaces runtime (see EnableRituals).
type RitualsOptions struct {
	SpaceOrigin     string // RITUALS_SPACE_ORIGIN, the ticket `aud`
	TicketPublicKey string // RITUALS_TICKET_PUBLIC_KEY, base64url 32 bytes
	Pool            *db.Pool
	Hub             RitualsHub
	RoomService     livekit.RoomService
	JWTSecret       string
}

type ritualsRuntime struct {
	origin      string
	pubKey      ed25519.PublicKey
	pool        *db.Pool
	hub         RitualsHub
	roomService livekit.RoomService
	now         func() time.Time
	// personSecret keys the per-Space person key (rituals_person.go).
	personSecret []byte
	// seatActivity gates the hub's activity hook (rituals_activity.go).
	seatActivity ritualsSeatActivityGate
}

var ritualsCurrent atomic.Pointer[ritualsRuntime]

// ritualsActive returns the Rituals runtime, or nil when RITUALS_MODE is off.
func ritualsActive() *ritualsRuntime { return ritualsCurrent.Load() }

// ValidateRitualsConfig checks the Rituals settings; main refuses to start
// in RITUALS_MODE when they are wrong.
func ValidateRitualsConfig(origin, ticketPublicKey string) error {
	if err := validateRitualsOrigin(origin); err != nil {
		return err
	}
	_, err := parseRitualsPublicKey(ticketPublicKey)
	return err
}

func validateRitualsOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("RITUALS_SPACE_ORIGIN must be a bare origin such as https://space.rit.al, got %q", origin)
	}
	return nil
}

func parseRitualsPublicKey(s string) (ed25519.PublicKey, error) {
	raw, ok := decodeRitualsB64(strings.TrimSpace(s))
	if !ok || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("RITUALS_TICKET_PUBLIC_KEY must be a 32-byte Ed25519 public key, base64url without padding")
	}
	return ed25519.PublicKey(raw), nil
}

// EnableRituals installs the process-wide Rituals runtime used by the hooks
// in upstream handlers and returns the router to mount at /api/rituals.
func EnableRituals(opts RitualsOptions) (chi.Router, error) {
	if err := validateRitualsOrigin(opts.SpaceOrigin); err != nil {
		return nil, err
	}
	pub, err := parseRitualsPublicKey(opts.TicketPublicKey)
	if err != nil {
		return nil, err
	}
	if opts.Pool == nil {
		return nil, errors.New("rituals: a database pool is required")
	}
	roomService := opts.RoomService
	if roomService == nil {
		roomService = livekit.NoopRoomService{}
	}
	rt := &ritualsRuntime{
		origin:      opts.SpaceOrigin,
		pubKey:      pub,
		pool:        opts.Pool,
		hub:         opts.Hub,
		roomService: roomService,
		now:         time.Now,
	}
	rt.personSecret = ritualsPersonKeySecret(opts.JWTSecret)
	ritualsCurrent.Store(rt)
	if rt.hub != nil {
		rt.hub.SetSubscribeHook(rt.pendingRemovalFrames)
		rt.hub.SetServerActivityHook(rt.noteSeatActivity)
	}
	return rt.routes(opts.JWTSecret), nil
}

// DisableRituals clears the runtime (BuildServer outside RITUALS_MODE), so
// a previous construction in the same process cannot leak into this one.
func DisableRituals() { ritualsCurrent.Store(nil) }

func (rt *ritualsRuntime) routes(jwtSecret string) chi.Router {
	r := chi.NewRouter()
	// Server to server from the Rituals API: the signed blob is the auth.
	// Both skip the global per-IP limiter (RitualsExemptServerToServer) so
	// the Rituals API's one egress IP never shares a bucket with browsers,
	// and each has its own per-IP bucket instead.
	r.With(IPRateLimiter(rate.Limit(600.0/60.0), 300)).Post(ritualsSyncPath, rt.handleSync)
	r.With(IPRateLimiter(rate.Limit(300.0/60.0), 60)).Post(ritualsFreshPath, rt.handleFresh)
	// Browser, before register: the signed ticket is the auth; under the
	// global limiter plus its own, narrower bucket.
	r.With(IPRateLimiter(rate.Limit(60.0/60.0), 30)).Post("/spaces/peek", rt.handlePeek)
	r.Group(func(r chi.Router) {
		r.Use(RequireAuth(jwtSecret, rt.pool))
		r.Use(UserRateLimiter(rate.Limit(30.0/60.0), 10))
		r.Post("/spaces/claim", rt.handleClaim)
	})
	return r
}

const (
	ritualsMount     = "/api/rituals"
	ritualsSyncPath  = "/spaces/sync"
	ritualsFreshPath = "/spaces/fresh"
)

// RitualsExemptServerToServer wraps the global per-IP limiter so it skips
// exactly POST /api/rituals/spaces/sync and /spaces/fresh, which have their
// own buckets in routes(). Every other request goes through limiter as before.
func RitualsExemptServerToServer(limiter func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		limited := limiter(next)
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodPost &&
				(req.URL.Path == ritualsMount+ritualsSyncPath || req.URL.Path == ritualsMount+ritualsFreshPath) {
				next.ServeHTTP(w, req)
				return
			}
			limited.ServeHTTP(w, req)
		})
	}
}

// ritualsSchemaSQL is applied at every start; every statement is idempotent.
var ritualsSchemaSQL = []string{
	`CREATE SCHEMA IF NOT EXISTS rituals`,
	`CREATE TABLE IF NOT EXISTS rituals.spaces (
		sp            TEXT        PRIMARY KEY,
		server_id     UUID        NOT NULL UNIQUE REFERENCES public.servers(id) ON DELETE CASCADE,
		name_iat      BIGINT      NOT NULL DEFAULT 0,
		last_sync_iat BIGINT      NOT NULL DEFAULT 0,
		created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
	)`,
	// The subs allowed by the last applied sync (NULL before the first one).
	// A claim whose ticket is not newer than that sync must be on the list,
	// so an unexpired ticket cannot re-admit someone Rituals removed.
	`ALTER TABLE rituals.spaces ADD COLUMN IF NOT EXISTS allowed_subs TEXT[]`,
	`CREATE TABLE IF NOT EXISTS rituals.seats (
		sp         TEXT        NOT NULL REFERENCES rituals.spaces(sp) ON DELETE CASCADE,
		sub        TEXT        NOT NULL,
		user_id    UUID        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		PRIMARY KEY (sp, user_id)
	)`,
	// The seat's last activity: set by every claim (new seat or re-open) and,
	// throttled, when its Hush user's connection subscribes to the space's
	// server, unsubscribes or disconnects (touchSeatActivity). The device cap
	// retires the least recently active first (retireOldSeats). Nullable with
	// no default and added here, not as a numbered migration, so the previous
	// release still boots on this schema (dbcompat refuses a schema_migrations
	// version past its own) and its inserts leave NULL. NULL means "never
	// recorded": ranking falls back to the creation / device sign-in recency.
	`ALTER TABLE rituals.seats ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ`,
	`CREATE INDEX IF NOT EXISTS seats_sp_sub_idx ON rituals.seats (sp, sub)`,
	`CREATE INDEX IF NOT EXISTS seats_user_id_idx ON rituals.seats (user_id)`,
	// user_id is SET NULL on user deletion so a consumed jti stays consumed.
	`CREATE TABLE IF NOT EXISTS rituals.registration_tickets (
		jti        TEXT        PRIMARY KEY,
		user_id    UUID        REFERENCES public.users(id) ON DELETE SET NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`,
	// Pending MLS remove requests (wire contract Item 2, D14): one row per
	// removed user x text channel x MLS device, replayed on subscribe until a
	// commit's removes hint, a re-seat, the 30-day TTL or the channel's
	// deletion clears it. No FK on user_id: the leaf outlives a deleted user.
	// The primary key serves the replay, hint and re-seat deletes; the
	// created_at index serves the TTL delete. Bounded per sync by the 64
	// device cap per user and the space's member rows (64 people x 5 device
	// seats, member_cap_override) and channel caps.
	`CREATE TABLE IF NOT EXISTS rituals.pending_mls_removals (
		channel_id UUID        NOT NULL REFERENCES public.channels(id) ON DELETE CASCADE,
		user_id    UUID        NOT NULL,
		device_id  TEXT        NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		PRIMARY KEY (channel_id, user_id, device_id)
	)`,
	`CREATE INDEX IF NOT EXISTS pending_mls_removals_created_idx ON rituals.pending_mls_removals (created_at)`,
}

// RitualsBootstrap creates the rituals schema and forces the Rituals instance
// policy (invite-only registration, no guild creation, no discovery). main
// calls it in RITUALS_MODE before seeding the handshake cache, so clients see
// the forced values from the first request.
func RitualsBootstrap(ctx context.Context, pool *db.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rituals bootstrap: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for _, stmt := range ritualsSchemaSQL {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("rituals bootstrap: schema: %w", err)
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE instance_config
		SET registration_mode = 'invite_only',
		    server_creation_policy = 'disabled',
		    guild_discovery = 'disabled'
		WHERE registration_mode <> 'invite_only'
		   OR server_creation_policy <> 'disabled'
		   OR guild_discovery <> 'disabled'`)
	if err != nil {
		return fmt.Errorf("rituals bootstrap: instance policy: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("rituals bootstrap: commit: %w", err)
	}
	slog.Info("rituals: schema ready, instance policy enforced", "instance_config_rows_changed", tag.RowsAffected())
	return nil
}
