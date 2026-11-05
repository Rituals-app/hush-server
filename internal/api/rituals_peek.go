package api

// Rituals fork: POST /api/rituals/spaces/peek {"ticket":"rt1..."}.
//
// Lets the Space client decide, before it creates or registers a Hush
// identity, whether to offer "Add this device" (this person is already seated
// from another device) or to register as usual. The ticket is verified exactly
// as /spaces/claim verifies it (signature, aud, exp, and the revocation check
// against the last sync) but its jti is NOT consumed and no session is needed:
// the signed ticket is the auth, as for /spaces/sync. Nothing is written.
//
// 200 {"claimed","selfSeated","othersSeated"}: claimed = the space row
// exists; selfSeated = a seat for (sp, sub) is bound to a Hush user;
// othersSeated = a seat for the same sp and a different sub is bound to a
// Hush user. Booleans only, never who or how many. An unknown space is all
// false. Errors {"error": code}: 400 bad_ticket, 403 ticket_expired |
// ticket_revoked. Rate limited per IP (its own bucket, below the global one).

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
)

type ritualsPeekResult struct {
	Claimed      bool `json:"claimed"`
	SelfSeated   bool `json:"selfSeated"`
	OthersSeated bool `json:"othersSeated"`
}

func (rt *ritualsRuntime) handlePeek(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, ritualsClaimBodyLimit)).Decode(&req); err != nil {
		writeRitualsError(w, errRitualsBadTicket)
		return
	}
	t, verr := rt.verifyTicket(req.Ticket)
	if verr != nil {
		writeRitualsError(w, verr)
		return
	}
	res, perr, err := rt.peekSpace(r.Context(), t)
	if err != nil {
		slog.Error("rituals peek", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "peek_failed"})
		return
	}
	if perr != nil {
		writeRitualsError(w, perr)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// peekSpace reads without the advisory lock: a racing claim can only turn a
// false into a true, and the client treats every hint as advisory.
func (rt *ritualsRuntime) peekSpace(ctx context.Context, t *ritualsTicket) (*ritualsPeekResult, *ritualsError, error) {
	var lastSyncIat int64
	var synced, subAllowed bool
	res := &ritualsPeekResult{}
	err := rt.pool.QueryRow(ctx, `
		SELECT last_sync_iat, allowed_subs IS NOT NULL,
		       COALESCE($2 = ANY(allowed_subs), false),
		       EXISTS (SELECT 1 FROM rituals.seats WHERE sp = $1 AND sub = $2),
		       EXISTS (SELECT 1 FROM rituals.seats WHERE sp = $1 AND sub <> $2)
		FROM rituals.spaces WHERE sp = $1`, t.Sp, t.Sub).
		Scan(&lastSyncIat, &synced, &subAllowed, &res.SelfSeated, &res.OthersSeated)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return &ritualsPeekResult{}, nil, nil
	case err != nil:
		return nil, nil, err
	case synced && t.Iat <= lastSyncIat && !subAllowed:
		// Same rule as claim: a removed person learns nothing about the space.
		return nil, &ritualsError{http.StatusForbidden, "ticket_revoked"}, nil
	}
	res.Claimed = true
	return res, nil, nil
}
