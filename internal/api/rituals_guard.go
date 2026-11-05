package api

// Rituals fork: one-line hooks called from upstream handlers. Each returns
// immediately (upstream behaviour) unless RITUALS_MODE enabled the runtime.
// Hooks named ritualsBlock* return true when they wrote a refusal; hooks
// named ritualsAllow*/ritualsRequire* return false when they wrote one.

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/hushhq/hush-server/internal/db"
	"github.com/hushhq/hush-server/internal/models"

	"github.com/google/uuid"
)

// ---------- registration ----------

// ritualsRegistrationMode keeps registration invite-only in Rituals mode even
// if instance_config was changed to "open" after startup.
func ritualsRegistrationMode(mode string) string {
	if ritualsActive() != nil && mode == "open" {
		return "invite_only"
	}
	return mode
}

// isRitualsTicketCode reports whether a register inviteCode is a Rituals
// ticket rather than an ordinary invite code.
func isRitualsTicketCode(code string) bool {
	return strings.HasPrefix(code, ritualsTicketPrefix)
}

// ritualsRegistrationGate verifies a ticket presented as the inviteCode and
// refuses an already-used jti. It returns the jti to consume once the user
// row exists (so a username collision does not burn the ticket).
func ritualsRegistrationGate(w http.ResponseWriter, r *http.Request, code string) (string, bool) {
	rt := ritualsActive()
	if rt == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Invalid invite code"})
		return "", false
	}
	t, verr := rt.verifyTicket(code)
	if verr != nil {
		writeRitualsError(w, verr)
		return "", false
	}
	var used bool
	if err := rt.pool.QueryRow(r.Context(),
		`SELECT EXISTS (SELECT 1 FROM rituals.registration_tickets WHERE jti = $1)`, t.Jti).Scan(&used); err != nil {
		slog.Error("rituals: check registration ticket", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "registration failed"})
		return "", false
	}
	if used {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "ticket_used"})
		return "", false
	}
	return t.Jti, true
}

// ritualsConsumeRegistrationTicket records the jti right after the user row
// was created. If a concurrent registration consumed it first (or the insert
// fails), the new user row is deleted again so one ticket creates at most one
// account. Returns false after writing the refusal.
func ritualsConsumeRegistrationTicket(w http.ResponseWriter, r *http.Request, jti, userID string) bool {
	if jti == "" {
		return true
	}
	rt := ritualsActive()
	if rt == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Invalid invite code"})
		return false
	}
	ctx := context.WithoutCancel(r.Context())
	tag, err := rt.pool.Exec(ctx, `
		INSERT INTO rituals.registration_tickets (jti, user_id) VALUES ($1, $2)
		ON CONFLICT (jti) DO NOTHING`, jti, userID)
	if err == nil && tag.RowsAffected() == 1 {
		return true
	}
	if _, derr := rt.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); derr != nil {
		slog.Error("rituals: undo registration after ticket conflict", "user_id", userID, "err", derr)
	}
	if err != nil {
		slog.Error("rituals: record registration ticket", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "registration failed"})
		return false
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "ticket_used"})
	return false
}

// ritualsBlockGuest turns POST /api/auth/guest off in Rituals mode.
func ritualsBlockGuest(w http.ResponseWriter) bool {
	if ritualsActive() == nil {
		return false
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	return true
}

// ---------- directory, search, DMs ----------

// ritualsRequireInstanceAdmin limits GET /api/instance/members (the full user
// directory) to instance admins in Rituals mode.
func ritualsRequireInstanceAdmin(w http.ResponseWriter, r *http.Request, store db.Store) bool {
	if ritualsActive() == nil {
		return true
	}
	role, err := store.GetUserRole(r.Context(), userIDFromContext(r.Context()))
	if err != nil {
		slog.Error("rituals: get user role", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify role"})
		return false
	}
	if role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return false
	}
	return true
}

// ritualsSearchUsers answers GET /api/guilds/users/search in Rituals mode with
// only the people who share a (non-DM) space with the caller. Returns true
// when it wrote the response.
func ritualsSearchUsers(w http.ResponseWriter, r *http.Request, query string, limit int) bool {
	rt := ritualsActive()
	if rt == nil {
		return false
	}
	callerID := userIDFromContext(r.Context())
	rows, err := rt.pool.Query(r.Context(), `
		SELECT DISTINCT u.id, u.username, u.display_name
		FROM users u
		JOIN server_members m  ON m.user_id = u.id
		JOIN servers s         ON s.id = m.server_id AND s.is_dm = false
		JOIN server_members me ON me.server_id = m.server_id AND me.user_id = $3
		WHERE u.username ILIKE $1 OR u.display_name ILIKE $1
		ORDER BY u.username
		LIMIT $2`, "%"+query+"%", limit, callerID)
	if err != nil {
		slog.Error("rituals: search co-members", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to search users"})
		return true
	}
	defer rows.Close()
	out := []models.UserSearchPublicResult{}
	for rows.Next() {
		var u models.UserSearchPublicResult
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName); err != nil {
			slog.Error("rituals: scan co-member", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to search users"})
			return true
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rituals: iterate co-members", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to search users"})
		return true
	}
	writeJSON(w, http.StatusOK, out)
	return true
}

// ritualsAllowDM limits POST /api/guilds/dm to people who share a (non-DM)
// space with the caller; anyone else looks like an unknown user.
func ritualsAllowDM(w http.ResponseWriter, r *http.Request, callerID, otherID string) bool {
	rt := ritualsActive()
	if rt == nil {
		return true
	}
	if _, err := uuid.Parse(otherID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return false
	}
	var shared bool
	if err := rt.pool.QueryRow(r.Context(), `
		SELECT EXISTS (
			SELECT 1 FROM server_members a
			JOIN server_members b ON b.server_id = a.server_id
			JOIN servers s        ON s.id = a.server_id AND s.is_dm = false
			WHERE a.user_id = $1 AND b.user_id = $2)`, callerID, otherID).Scan(&shared); err != nil {
		slog.Error("rituals: shared space check", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to look up user"})
		return false
	}
	if !shared {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return false
	}
	return true
}

// ---------- MLS ----------

// ritualsRequireChannelMember enforces membership on the MLS group routes
// (GroupInfo GET/PUT, commit, commits; text and voice) in Rituals mode.
func ritualsRequireChannelMember(w http.ResponseWriter, r *http.Request, store db.Store, channelID string) bool {
	if ritualsActive() == nil {
		return true
	}
	ok, err := store.IsChannelMember(r.Context(), channelID, userIDFromContext(r.Context()))
	if err != nil {
		slog.Error("rituals: channel membership check", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "check membership failed"})
		return false
	}
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not a channel member"})
		return false
	}
	return true
}

// ritualsRequireGuildMember enforces guild membership on the guild-metadata
// GroupInfo read in Rituals mode.
func ritualsRequireGuildMember(w http.ResponseWriter, r *http.Request, store db.Store, guildID string) bool {
	if ritualsActive() == nil {
		return true
	}
	if _, err := store.GetServerMemberLevel(r.Context(), guildID, userIDFromContext(r.Context())); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "guild membership required"})
		return false
	}
	return true
}

// ritualsRequireOwnKeyPackages: in Rituals mode a caller may only consume its
// own KeyPackages (the web client never consumes anyone else's; upstream let
// any account burn another user's supply).
func ritualsRequireOwnKeyPackages(w http.ResponseWriter, r *http.Request, targetUserID string) bool {
	if ritualsActive() == nil || targetUserID == userIDFromContext(r.Context()) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	return false
}

// ritualsRequireOwnWelcome: in Rituals mode a pending Welcome can only be
// deleted by its recipient.
func ritualsRequireOwnWelcome(w http.ResponseWriter, r *http.Request, store db.Store, welcomeID string) bool {
	if ritualsActive() == nil {
		return true
	}
	welcomes, err := store.GetPendingWelcomes(r.Context(), userIDFromContext(r.Context()))
	if err != nil {
		slog.Error("rituals: list pending welcomes", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete pending welcome"})
		return false
	}
	for _, pw := range welcomes {
		if pw.ID == welcomeID {
			return true
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "welcome not found"})
	return false
}

// ---------- Rituals-owned space lifecycle ----------

func ritualsIsSpace(ctx context.Context, serverID string) (bool, error) {
	rt := ritualsActive()
	if rt == nil {
		return false, nil
	}
	if _, err := uuid.Parse(serverID); err != nil {
		return false, nil
	}
	var exists bool
	err := rt.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rituals.spaces WHERE server_id = $1)`, serverID).Scan(&exists)
	return exists, err
}

// ritualsBlockManagedSpace refuses lifecycle actions that belong to Rituals on
// a Rituals space: delete, leave, join without an invite.
func ritualsBlockManagedSpace(w http.ResponseWriter, r *http.Request, serverID string) bool {
	space, err := ritualsIsSpace(r.Context(), serverID)
	if err != nil {
		slog.Error("rituals: space lookup", "server_id", serverID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return true
	}
	if space {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "managed_by_rituals"})
		return true
	}
	return false
}

// ritualsBlockInvite refuses invite creation in Rituals mode: spaces are
// entered with Rituals tickets only, and an invite to any other guild (a DM)
// would also open invite-only registration to strangers.
func ritualsBlockInvite(w http.ResponseWriter, r *http.Request, serverID string) bool {
	if ritualsActive() == nil {
		return false
	}
	if ritualsBlockManagedSpace(w, r, serverID) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "invites_disabled"})
	return true
}

// ritualsBlockRoleChange refuses, on a Rituals space, any role change that
// touches the task owner's level (admin, 2) or would grant admin/owner: that
// covers demoting the task owner and every form of ownership transfer.
func ritualsBlockRoleChange(w http.ResponseWriter, r *http.Request, serverID string, targetLevel, newLevel int) bool {
	if targetLevel < models.PermissionLevelAdmin && newLevel < models.PermissionLevelAdmin {
		return false
	}
	return ritualsBlockManagedSpace(w, r, serverID)
}
