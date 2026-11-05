package api

// Rituals fork: POST /api/rituals/spaces/claim and POST /api/rituals/spaces/sync.
//
// Both run in one transaction holding pg_advisory_xact_lock on the space id
// (sp), so concurrent first claims create exactly one guild and a sync never
// interleaves with a claim. Broadcasts happen after commit.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/hushhq/hush-server/internal/models"

	"github.com/jackc/pgx/v5"
)

const (
	ritualsSpaceMemberCap = 64
	// Namespace for the two-key pg_advisory_xact_lock(int4, int4) form ("RTS1").
	ritualsAdvisoryClass  = int32(0x52545331)
	ritualsClaimBodyLimit = 8 << 10
	ritualsSyncBodyLimit  = 32 << 10
	ritualsEffectsTimeout = 20 * time.Second
	ritualsVoiceEvictWait = 4 * time.Second
)

// ritualsTemplate is the channel set of a new space: upstream's system
// channel plus one text channel and one voice channel.
var ritualsTemplate = []models.TemplateChannel{
	{Name: "system", Type: "system", Position: -1},
	{Name: "general", Type: "text", Position: 0},
	{Name: "Voice", Type: "voice", Position: 1},
}

func ritualsLockSpace(ctx context.Context, tx pgx.Tx, sp string) error {
	// sp is validated 64-hex by the verifier; its first 4 bytes key the lock.
	b, err := hex.DecodeString(sp[:8])
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::int4, $2::int4)`,
		ritualsAdvisoryClass, int32(binary.BigEndian.Uint32(b)))
	return err
}

func ritualsRecountMembers(ctx context.Context, tx pgx.Tx, serverID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE servers SET member_count = (SELECT COUNT(*) FROM server_members WHERE server_id = $1)
		WHERE id = $1`, serverID)
	return err
}

// ---------- claim ----------

type ritualsClaimResult struct {
	serverID       string
	channelID      string
	level          int
	memberInserted bool
	levelRaised    bool
	renamed        bool
	metadata       []byte
}

// handleClaim: POST /api/rituals/spaces/claim {"ticket":"rt1..."} (RequireAuth).
// 200 {"serverId","channelId"}; errors {"error": code}: 400 bad_ticket,
// 403 ticket_expired | ticket_revoked | banned | space_full | guest_not_allowed,
// 409 seat_conflict.
func (rt *ritualsRuntime) handleClaim(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	if isGuestFromContext(r.Context()) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "guest_not_allowed"})
		return
	}
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
	res, cerr, err := rt.claimSpace(r.Context(), userID, t)
	if err != nil {
		slog.Error("rituals claim", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "claim_failed"})
		return
	}
	if cerr != nil {
		writeRitualsError(w, cerr)
		return
	}
	rt.announceClaim(context.WithoutCancel(r.Context()), userID, res)
	writeJSON(w, http.StatusOK, map[string]string{"serverId": res.serverID, "channelId": res.channelID})
}

func (rt *ritualsRuntime) claimSpace(ctx context.Context, userID string, t *ritualsTicket) (*ritualsClaimResult, *ritualsError, error) {
	tx, err := rt.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := ritualsLockSpace(ctx, tx, t.Sp); err != nil {
		return nil, nil, err
	}

	res := &ritualsClaimResult{level: models.PermissionLevelMember, metadata: plaintextMetadata(t.Name)}
	if t.Role == "owner" {
		res.level = models.PermissionLevelAdmin
	}

	// Find or create the space.
	var nameIat, lastSyncIat int64
	var synced, subAllowed bool
	created := false
	err = tx.QueryRow(ctx, `
		SELECT server_id, name_iat, last_sync_iat, allowed_subs IS NOT NULL,
		       COALESCE($2 = ANY(allowed_subs), false)
		FROM rituals.spaces WHERE sp = $1`, t.Sp, t.Sub).
		Scan(&res.serverID, &nameIat, &lastSyncIat, &synced, &subAllowed)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if res.serverID, err = ritualsCreateSpace(ctx, tx, t.Sp, res.metadata, t.Iat); err != nil {
			return nil, nil, err
		}
		created = true
	case err != nil:
		return nil, nil, err
	case synced && t.Iat <= lastSyncIat && !subAllowed:
		// A sync at least as new as this ticket says this person is no
		// longer on the task: an older ticket must not bring them back.
		return nil, &ritualsError{http.StatusForbidden, "ticket_revoked"}, nil
	}

	var banned bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM bans
			WHERE server_id = $1 AND user_id = $2
			  AND lifted_at IS NULL
			  AND (expires_at IS NULL OR expires_at > now()))`,
		res.serverID, userID).Scan(&banned); err != nil {
		return nil, nil, err
	}
	if banned {
		return nil, &ritualsError{http.StatusForbidden, "banned"}, nil
	}

	// Seat: one sub per Hush user per space; a sub may hold several users.
	var seatSub string
	err = tx.QueryRow(ctx, `SELECT sub FROM rituals.seats WHERE sp = $1 AND user_id = $2`, t.Sp, userID).Scan(&seatSub)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if _, err := tx.Exec(ctx, `INSERT INTO rituals.seats (sp, sub, user_id) VALUES ($1, $2, $3)`, t.Sp, t.Sub, userID); err != nil {
			return nil, nil, err
		}
	case err != nil:
		return nil, nil, err
	case seatSub != t.Sub:
		return nil, &ritualsError{http.StatusConflict, "seat_conflict"}, nil
	}

	// Membership: insert at the ticket's level, or raise a lower level.
	var current int
	err = tx.QueryRow(ctx, `SELECT permission_level FROM server_members WHERE server_id = $1 AND user_id = $2`,
		res.serverID, userID).Scan(&current)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM server_members WHERE server_id = $1`, res.serverID).Scan(&count); err != nil {
			return nil, nil, err
		}
		if count >= ritualsSpaceMemberCap {
			return nil, &ritualsError{http.StatusForbidden, "space_full"}, nil
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO server_members (server_id, user_id, permission_level)
			VALUES ($1, $2, $3)
			ON CONFLICT (server_id, user_id) WHERE user_id IS NOT NULL DO NOTHING`,
			res.serverID, userID, res.level)
		if err != nil {
			return nil, nil, err
		}
		res.memberInserted = tag.RowsAffected() == 1
	case err != nil:
		return nil, nil, err
	case current < res.level:
		if _, err := tx.Exec(ctx, `
			UPDATE server_members SET permission_level = $3
			WHERE server_id = $1 AND user_id = $2 AND permission_level < $3`,
			res.serverID, userID, res.level); err != nil {
			return nil, nil, err
		}
		res.levelRaised = true
	default:
		res.level = current
	}

	// Name refresh from a newer ticket.
	if !created && t.Iat > nameIat {
		tag, err := tx.Exec(ctx, `
			UPDATE servers SET encrypted_metadata = $2
			WHERE id = $1 AND encrypted_metadata IS DISTINCT FROM $2`, res.serverID, res.metadata)
		if err != nil {
			return nil, nil, err
		}
		res.renamed = tag.RowsAffected() > 0
		if _, err := tx.Exec(ctx, `UPDATE rituals.spaces SET name_iat = $2 WHERE sp = $1`, t.Sp, t.Iat); err != nil {
			return nil, nil, err
		}
	}
	if res.memberInserted {
		if err := ritualsRecountMembers(ctx, tx, res.serverID); err != nil {
			return nil, nil, err
		}
	}
	// channelId is the first text channel; "" if the owner deleted them all.
	err = tx.QueryRow(ctx, `
		SELECT id FROM channels WHERE server_id = $1 AND type = 'text'
		ORDER BY position, id LIMIT 1`, res.serverID).Scan(&res.channelID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return res, nil, nil
}

// ritualsCreateSpace creates the guild of a new space inside the claim
// transaction, modelled on CreateDMGuild and the template channels of
// createServer: closed, not discoverable, member cap 64, plaintext names.
func ritualsCreateSpace(ctx context.Context, tx pgx.Tx, sp string, metadata []byte, iat int64) (string, error) {
	var serverID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO servers (encrypted_metadata, access_policy, discoverable, member_cap_override)
		VALUES ($1, 'closed', false, $2)
		RETURNING id`, metadata, ritualsSpaceMemberCap).Scan(&serverID); err != nil {
		return "", fmt.Errorf("create space guild: %w", err)
	}
	for _, tc := range ritualsTemplate {
		if _, err := tx.Exec(ctx, `
			INSERT INTO channels (server_id, encrypted_metadata, type, position)
			VALUES ($1, $2, $3, $4)`,
			serverID, plaintextMetadata(tc.Name), tc.Type, tc.Position); err != nil {
			return "", fmt.Errorf("create space channel %q: %w", tc.Name, err)
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE servers SET
			text_channel_count  = (SELECT COUNT(*) FROM channels WHERE server_id = $1 AND type = 'text'),
			voice_channel_count = (SELECT COUNT(*) FROM channels WHERE server_id = $1 AND type = 'voice')
		WHERE id = $1`, serverID); err != nil {
		return "", fmt.Errorf("count space channels: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rituals.spaces (sp, server_id, name_iat) VALUES ($1, $2, $3)`,
		sp, serverID, iat); err != nil {
		return "", fmt.Errorf("record space: %w", err)
	}
	return serverID, nil
}

// announceClaim sends the same frames as an invite claim when a member row
// was inserted (invites.go), plus role and name changes.
func (rt *ritualsRuntime) announceClaim(ctx context.Context, userID string, res *ritualsClaimResult) {
	if rt.hub == nil {
		return
	}
	if res.memberInserted {
		member := map[string]interface{}{"id": userID, "permissionLevel": res.level}
		if u, err := rt.pool.GetUserByID(ctx, userID); err == nil && u != nil {
			member["username"] = u.Username
			member["displayName"] = u.DisplayName
		}
		msg, _ := json.Marshal(map[string]interface{}{
			"type":      "member_joined",
			"server_id": res.serverID,
			"member":    member,
		})
		rt.hub.BroadcastToServer(res.serverID, msg)
		rt.hub.BroadcastToUser(userID, msg)
		EmitSystemMessage(ctx, rt.pool, rt.hub, res.serverID, "member_joined", userID, nil, "", nil)
	} else if res.levelRaised {
		msg, _ := json.Marshal(map[string]interface{}{
			"type":             "member_role_changed",
			"server_id":        res.serverID,
			"user_id":          userID,
			"permission_level": res.level,
		})
		rt.hub.BroadcastToServer(res.serverID, msg)
	}
	if res.renamed {
		rt.broadcastRename(res.serverID, res.metadata)
	}
}

func (rt *ritualsRuntime) broadcastRename(serverID string, metadata []byte) {
	if rt.hub == nil {
		return
	}
	msg, _ := json.Marshal(map[string]interface{}{
		"type":              "server_updated",
		"server_id":         serverID,
		"encryptedMetadata": metadata,
	})
	rt.hub.BroadcastToServer(serverID, msg)
}

// ---------- sync ----------

type ritualsSyncResult struct {
	unknown        bool
	stale          bool
	serverID       string
	removedSeats   []string // Hush users whose seat was deleted
	removedMembers []string // of those, the ones that still had a member row
	textChannels   []string
	voiceChannels  []string
	renamed        bool
	metadata       []byte
}

// handleSync: POST /api/rituals/spaces/sync {"sync":"rts1..."}; no user auth,
// the signed blob is the auth. 200 {"ok":true,"removed":N} |
// {"ok":true,"stale":true} | {"ok":true,"unknown":true}; 400 bad_sync,
// 403 sync_expired.
func (rt *ritualsRuntime) handleSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Sync string `json:"sync"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, ritualsSyncBodyLimit)).Decode(&req); err != nil {
		writeRitualsError(w, errRitualsBadSync)
		return
	}
	p, verr := rt.verifySync(req.Sync)
	if verr != nil {
		writeRitualsError(w, verr)
		return
	}
	res, err := rt.applySync(r.Context(), p)
	if err != nil {
		slog.Error("rituals sync", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sync_failed"})
		return
	}
	switch {
	case res.unknown:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "unknown": true})
	case res.stale:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "stale": true})
	default:
		rt.announceSync(res)
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "removed": len(res.removedSeats)})
	}
}

func (rt *ritualsRuntime) applySync(ctx context.Context, p *ritualsSync) (*ritualsSyncResult, error) {
	tx, err := rt.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := ritualsLockSpace(ctx, tx, p.Sp); err != nil {
		return nil, err
	}

	res := &ritualsSyncResult{}
	var lastIat, nameIat int64
	var synced bool
	var prevAllowed []string
	err = tx.QueryRow(ctx, `
		SELECT server_id, last_sync_iat, name_iat, allowed_subs IS NOT NULL,
		       COALESCE(allowed_subs, '{}'::text[])
		FROM rituals.spaces WHERE sp = $1`, p.Sp).
		Scan(&res.serverID, &lastIat, &nameIat, &synced, &prevAllowed)
	if errors.Is(err, pgx.ErrNoRows) {
		res.unknown = true
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	// Strictly older than the last applied sync: stale. An equal iat is still
	// applied, narrowing to the intersection: a sync only removes people, so
	// two same-second syncs give the same result in either order and a
	// removal is never lost to second-granularity timestamps.
	if p.Iat < lastIat {
		res.stale = true
		return res, nil
	}
	allowed := p.Subs
	if synced && p.Iat == lastIat {
		allowed = ritualsIntersect(prevAllowed, p.Subs)
	}

	rows, err := tx.Query(ctx, `
		DELETE FROM rituals.seats
		WHERE sp = $1 AND NOT (sub = ANY($2::text[]))
		RETURNING user_id`, p.Sp, allowed)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			rows.Close()
			return nil, err
		}
		res.removedSeats = append(res.removedSeats, uid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, uid := range res.removedSeats {
		tag, err := tx.Exec(ctx, `DELETE FROM server_members WHERE server_id = $1 AND user_id = $2`, res.serverID, uid)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() > 0 {
			res.removedMembers = append(res.removedMembers, uid)
		}
	}

	if p.Name != nil && p.Iat >= nameIat {
		res.metadata = plaintextMetadata(*p.Name)
		tag, err := tx.Exec(ctx, `
			UPDATE servers SET encrypted_metadata = $2
			WHERE id = $1 AND encrypted_metadata IS DISTINCT FROM $2`, res.serverID, res.metadata)
		if err != nil {
			return nil, err
		}
		res.renamed = tag.RowsAffected() > 0
		if _, err := tx.Exec(ctx, `UPDATE rituals.spaces SET name_iat = $2 WHERE sp = $1`, p.Sp, p.Iat); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE rituals.spaces SET last_sync_iat = $2, allowed_subs = $3::text[]
		WHERE sp = $1`, p.Sp, p.Iat, allowed); err != nil {
		return nil, err
	}

	if len(res.removedMembers) > 0 {
		if err := ritualsRecountMembers(ctx, tx, res.serverID); err != nil {
			return nil, err
		}
		chRows, err := tx.Query(ctx, `
			SELECT id, type FROM channels
			WHERE server_id = $1 AND type IN ('text', 'voice')
			ORDER BY position, id`, res.serverID)
		if err != nil {
			return nil, err
		}
		for chRows.Next() {
			var id, typ string
			if err := chRows.Scan(&id, &typ); err != nil {
				chRows.Close()
				return nil, err
			}
			if typ == "voice" {
				res.voiceChannels = append(res.voiceChannels, id)
			} else {
				res.textChannels = append(res.textChannels, id)
			}
		}
		chRows.Close()
		if err := chRows.Err(); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

func ritualsIntersect(a, b []string) []string {
	keep := make(map[string]struct{}, len(a))
	for _, s := range a {
		keep[s] = struct{}{}
	}
	out := make([]string, 0, len(b))
	for _, s := range b {
		if _, ok := keep[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// announceSync gives every removed member the effects of a moderation kick
// (moderation.go: member_kicked frame, LiveKit eviction, forced reconnect)
// plus server-built MLS remove requests, which the web client's
// useTextChannelMLSCommitListener commits from any online member (best
// effort: nobody online means the leaf stays until a later commit).
func (rt *ritualsRuntime) announceSync(res *ritualsSyncResult) {
	if res.renamed {
		rt.broadcastRename(res.serverID, res.metadata)
	}
	if len(res.removedMembers) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), ritualsEffectsTimeout)
	defer cancel()
	removed := append([]string(nil), res.removedMembers...)
	if rt.hub != nil {
		for _, uid := range removed {
			// No acting user exists for a Rituals-side removal, so the timeline
			// entry is "member_left" by the removed person; the WS frame is the
			// kick frame so their clients drop the space like after a kick.
			EmitSystemMessage(ctx, rt.pool, rt.hub, res.serverID, "member_left", uid, nil, "", nil)
			msg, _ := json.Marshal(map[string]interface{}{
				"type":      "member_kicked",
				"server_id": res.serverID,
				"user_id":   uid,
			})
			rt.hub.BroadcastToServer(res.serverID, msg)
			rt.broadcastMLSRemovals(ctx, uid, res.textChannels)
		}
		hub := rt.hub
		time.AfterFunc(500*time.Millisecond, func() {
			for _, uid := range removed {
				hub.DisconnectUser(uid)
			}
		})
	}
	if len(res.voiceChannels) > 0 {
		voice := append([]string(nil), res.voiceChannels...)
		go rt.evictFromVoice(removed, voice)
	}
}

func (rt *ritualsRuntime) broadcastMLSRemovals(ctx context.Context, userID string, textChannels []string) {
	if len(textChannels) == 0 {
		return
	}
	devices, err := rt.pool.ListDeviceIDsForUser(ctx, userID)
	if err != nil {
		slog.Warn("rituals sync: list devices for MLS removal", "user_id", userID, "err", err)
		return
	}
	for _, channelID := range textChannels {
		for _, deviceID := range devices {
			// Same shape as handleMLSLeaveProposal; requester ids come from
			// the server, never from a client.
			frame, _ := json.Marshal(map[string]string{
				"type":                "mls.add_request",
				"channel_id":          channelID,
				"action":              "remove",
				"requester_id":        userID,
				"requester_device_id": deviceID,
			})
			rt.hub.Broadcast(channelID, frame, "")
		}
	}
}

func (rt *ritualsRuntime) evictFromVoice(userIDs, voiceChannels []string) {
	for _, uid := range userIDs {
		for _, channelID := range voiceChannels {
			ctx, cancel := context.WithTimeout(context.Background(), ritualsVoiceEvictWait)
			room := "channel-" + channelID
			if err := rt.roomService.RemoveParticipant(ctx, room, uid); err != nil {
				slog.Error("rituals sync: livekit eviction", "room", room, "user_id", uid, "err", err)
			}
			cancel()
		}
	}
}
