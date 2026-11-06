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
	// ritualsSpaceMemberCap counts people, not devices: every seated person
	// counts once however many devices they hold, and every member row
	// without a seat counts once (rituals_spaces.go ritualsPeopleCount).
	ritualsSpaceMemberCap = 64
	// ritualsSeatsPerPerson is the most seats (devices) one person holds in
	// one space. A claim for a further device retires that person's least
	// recently active seat through the revoke path, so a storage-less browser
	// opening the space again and again cannot fill it.
	ritualsSeatsPerPerson = 5
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
	selfSeated     bool
	othersSeated   bool
	personKey      string
	// The person's older seats retired by this claim (ritualsSeatsPerPerson):
	// retired lists every deleted seat, retiredMembers those that still had a
	// member row, and the channels are the space's, for the removal effects.
	retired        []string
	retiredMembers []string
	textChannels   []string
	voiceChannels  []string
}

// handleClaim: POST /api/rituals/spaces/claim {"ticket":"rt1..."} (RequireAuth).
// 200 {"serverId","channelId","selfSeated","othersSeated"}. selfSeated is true
// when this Rituals person (the ticket's sub) is also a member of this space
// from another Hush user, i.e. another device of theirs that still has a
// member row (a seat whose member row is gone, for example after an in-frame
// kick, does not count): the client may then say "Earlier messages are on
// your other device" truthfully and offer to link this device. othersSeated
// is true when someone else (a different sub) holds a seat, i.e. the space
// has people in it already. Neither names anyone.
// A new seat for a person who already holds ritualsSeatsPerPerson seats here
// retires their least recently active seats first (retireOldSeats).
// Before registering, the same hints come from POST /spaces/peek (rituals_peek.go),
// where selfSeated means any seat for the sub, since no Hush user exists yet.
// Errors {"error": code}: 400 bad_ticket,
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
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"serverId":     res.serverID,
		"channelId":    res.channelID,
		"selfSeated":   res.selfSeated,
		"othersSeated": res.othersSeated,
	})
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

	res := &ritualsClaimResult{level: models.PermissionLevelMember, metadata: plaintextMetadata(t.Name),
		personKey: rt.personKey(t.Sp, t.Sub)}
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

	// Seat: one sub per Hush user per space; a sub may hold several users,
	// at most ritualsSeatsPerPerson of them.
	var seatSub string
	err = tx.QueryRow(ctx, `SELECT sub FROM rituals.seats WHERE sp = $1 AND user_id = $2`, t.Sp, userID).Scan(&seatSub)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if err := rt.retireOldSeats(ctx, tx, t, userID, res); err != nil {
			return nil, nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO rituals.seats (sp, sub, user_id) VALUES ($1, $2, $3)`, t.Sp, t.Sub, userID); err != nil {
			return nil, nil, err
		}
	case err != nil:
		return nil, nil, err
	case seatSub != t.Sub:
		return nil, &ritualsError{http.StatusConflict, "seat_conflict"}, nil
	}
	// A re-seated person must not be removed again by a stale pending
	// remove request (wire contract Item 2, D16).
	if err := ritualsClearPendingForSeat(ctx, tx, userID, res.serverID); err != nil {
		return nil, nil, err
	}
	// selfSeated: another device of this person that is still a member here
	// (its seat and its member row). It also decides the person cap below: a
	// person already present is not a new person.
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		           SELECT 1 FROM rituals.seats s
		           JOIN server_members sm ON sm.server_id = $4 AND sm.user_id = s.user_id
		           WHERE s.sp = $1 AND s.sub = $2 AND s.user_id <> $3),
		       EXISTS (SELECT 1 FROM rituals.seats WHERE sp = $1 AND sub <> $2)`,
		t.Sp, t.Sub, userID, res.serverID).Scan(&res.selfSeated, &res.othersSeated); err != nil {
		return nil, nil, err
	}

	// Membership: insert at the ticket's level, or raise a lower level.
	var current int
	err = tx.QueryRow(ctx, `SELECT permission_level FROM server_members WHERE server_id = $1 AND user_id = $2`,
		res.serverID, userID).Scan(&current)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// The cap counts people: a further device of a person already here
		// is not a new person (its device count is bounded by the seat cap).
		if !res.selfSeated {
			count, err := ritualsPeopleCount(ctx, tx, t.Sp, res.serverID)
			if err != nil {
				return nil, nil, err
			}
			if count >= ritualsSpaceMemberCap {
				return nil, &ritualsError{http.StatusForbidden, "space_full"}, nil
			}
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
	if res.memberInserted && len(res.retiredMembers) == 0 {
		// (A retirement recounts below, after the new row is in.)
		if err := ritualsRecountMembers(ctx, tx, res.serverID); err != nil {
			return nil, nil, err
		}
	}
	if len(res.retiredMembers) > 0 {
		if res.textChannels, res.voiceChannels, err = ritualsRemovalEffects(ctx, tx, res.serverID, res.retiredMembers); err != nil {
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

// ritualsPeopleCount is the number of people in a space for the member cap:
// each seated person (sub) once however many devices they hold, plus each
// member row without a seat (a non-Rituals or federated member) once.
func ritualsPeopleCount(ctx context.Context, tx pgx.Tx, sp, serverID string) (int, error) {
	var people int
	err := tx.QueryRow(ctx, `
		SELECT COUNT(DISTINCT s.sub) + COUNT(*) FILTER (WHERE s.sub IS NULL)
		FROM server_members sm
		LEFT JOIN rituals.seats s ON s.sp = $2 AND s.user_id = sm.user_id
		WHERE sm.server_id = $1`, serverID, sp).Scan(&people)
	return people, err
}

// retireOldSeats runs inside the claim transaction before a new seat for
// (t.Sp, t.Sub) is inserted. When the person already holds
// ritualsSeatsPerPerson or more seats here, it retires their least recently
// active seats until the new one fits, never the claiming user, through the
// same per-user removal the revoke path uses (seat, member row, pending MLS
// removals; the frames follow after commit in announceClaim). Activity is the
// latest of the seat's creation and its Hush user's last device sign-in or
// device registration (device_keys.last_seen, set on every challenge login;
// devices.last_seen, set on credential upload), oldest first. An
// in-use device retired here is dropped from the space like a revoke; its
// next open from Rituals claims a seat again (same sub, not banned).
func (rt *ritualsRuntime) retireOldSeats(ctx context.Context, tx pgx.Tx, t *ritualsTicket, userID string, res *ritualsClaimResult) error {
	var held int
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM rituals.seats WHERE sp = $1 AND sub = $2 AND user_id <> $3`,
		t.Sp, t.Sub, userID).Scan(&held); err != nil {
		return err
	}
	excess := held - (ritualsSeatsPerPerson - 1)
	if excess <= 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT s.user_id::text
		FROM rituals.seats s
		WHERE s.sp = $1 AND s.sub = $2 AND s.user_id <> $3
		ORDER BY GREATEST(
		           s.created_at,
		           (SELECT MAX(dk.last_seen) FROM device_keys dk WHERE dk.user_id = s.user_id),
		           (SELECT MAX(d.last_seen) FROM devices d WHERE d.user_id = s.user_id)),
		         s.created_at, s.user_id
		LIMIT $4`, t.Sp, t.Sub, userID, excess)
	if err != nil {
		return err
	}
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			rows.Close()
			return err
		}
		res.retired = append(res.retired, uid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM rituals.seats WHERE sp = $1 AND user_id = ANY($2::uuid[])`,
		t.Sp, res.retired); err != nil {
		return err
	}
	res.retiredMembers, err = ritualsDropMembers(ctx, tx, res.serverID, res.retired)
	return err
}

// ritualsDropMembers deletes the member rows of users whose seats were just
// deleted and returns the ones that had a row (shared by sync and claim).
func ritualsDropMembers(ctx context.Context, tx pgx.Tx, serverID string, userIDs []string) ([]string, error) {
	var removed []string
	for _, uid := range userIDs {
		tag, err := tx.Exec(ctx, `DELETE FROM server_members WHERE server_id = $1 AND user_id = $2`, serverID, uid)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() > 0 {
			removed = append(removed, uid)
		}
	}
	return removed, nil
}

// ritualsRemovalEffects is the in-transaction rest of a removal of member
// rows (shared by sync and claim): recount, list the space's text and voice
// channels for the after-commit frames, and record the pending MLS remove
// requests, so a crash after the seat deletion cannot lose them (wire
// contract Item 2, D14). It always prunes expired pending removals.
func ritualsRemovalEffects(ctx context.Context, tx pgx.Tx, serverID string, removedMembers []string) (text, voice []string, err error) {
	if len(removedMembers) > 0 {
		if err := ritualsRecountMembers(ctx, tx, serverID); err != nil {
			return nil, nil, err
		}
		chRows, err := tx.Query(ctx, `
			SELECT id, type FROM channels
			WHERE server_id = $1 AND type IN ('text', 'voice')
			ORDER BY position, id`, serverID)
		if err != nil {
			return nil, nil, err
		}
		for chRows.Next() {
			var id, typ string
			if err := chRows.Scan(&id, &typ); err != nil {
				chRows.Close()
				return nil, nil, err
			}
			if typ == "voice" {
				voice = append(voice, id)
			} else {
				text = append(text, id)
			}
		}
		chRows.Close()
		if err := chRows.Err(); err != nil {
			return nil, nil, err
		}
	}
	if err := ritualsRecordPendingRemovals(ctx, tx, text, removedMembers); err != nil {
		return nil, nil, err
	}
	return text, voice, nil
}

// ritualsJoinEventType is the system message for a new member row: a later
// seat of a person already seated here is that person on a new device, not
// a new member joining.
func ritualsJoinEventType(res *ritualsClaimResult) string {
	if res.selfSeated {
		return "member_new_device"
	}
	return "member_joined"
}

// announceClaim sends the same frames as an invite claim when a member row
// was inserted (invites.go), plus role and name changes.
func (rt *ritualsRuntime) announceClaim(ctx context.Context, userID string, res *ritualsClaimResult) {
	// The person's retired older devices get the revoke effects. No timeline
	// line: the person has not left, and this claim adds its own line.
	rt.announceRemovals(res.serverID, res.retiredMembers, nil, res.textChannels, res.voiceChannels)
	if rt.hub == nil {
		return
	}
	if res.memberInserted {
		member := map[string]interface{}{"id": userID, "permissionLevel": res.level}
		if res.personKey != "" {
			member["personKey"] = res.personKey
		}
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
		EmitSystemMessage(ctx, rt.pool, rt.hub, res.serverID, ritualsJoinEventType(res), userID, nil, "", nil)
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
	leftActors     []string // one of removedMembers per removed person (sub)
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
		RETURNING user_id, sub, created_at`, p.Sp, allowed)
	if err != nil {
		return nil, err
	}
	type removedSeat struct {
		sub     string
		created time.Time
	}
	seats := map[string]removedSeat{}
	for rows.Next() {
		var uid string
		var seat removedSeat
		if err := rows.Scan(&uid, &seat.sub, &seat.created); err != nil {
			rows.Close()
			return nil, err
		}
		res.removedSeats = append(res.removedSeats, uid)
		seats[uid] = seat
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if res.removedMembers, err = ritualsDropMembers(ctx, tx, res.serverID, res.removedSeats); err != nil {
		return nil, err
	}
	res.leftActors = ritualsOnePerPerson(res.removedMembers, func(uid string) (string, time.Time) {
		return seats[uid].sub, seats[uid].created
	})

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

	if res.textChannels, res.voiceChannels, err = ritualsRemovalEffects(ctx, tx, res.serverID, res.removedMembers); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// ritualsOnePerPerson keeps one user per person (sub) from userIDs, in first
// appearance order: the one with the newest seat, the person's latest device.
func ritualsOnePerPerson(userIDs []string, seat func(uid string) (sub string, created time.Time)) []string {
	pick := map[string]string{}
	var order []string
	for _, uid := range userIDs {
		sub, created := seat(uid)
		cur, ok := pick[sub]
		if !ok {
			order = append(order, sub)
			pick[sub] = uid
			continue
		}
		if _, curCreated := seat(cur); created.After(curCreated) {
			pick[sub] = uid
		}
	}
	out := make([]string, 0, len(order))
	for _, sub := range order {
		out = append(out, pick[sub])
	}
	return out
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
// (announceRemovals) and writes one "member_left" line per removed person,
// not one per device.
func (rt *ritualsRuntime) announceSync(res *ritualsSyncResult) {
	if res.renamed {
		rt.broadcastRename(res.serverID, res.metadata)
	}
	rt.announceRemovals(res.serverID, res.removedMembers, res.leftActors, res.textChannels, res.voiceChannels)
}

// announceRemovals gives every removed member (one Hush user, i.e. one
// device) the effects of a moderation kick (moderation.go: member_kicked
// frame, LiveKit eviction, forced reconnect) plus server-built MLS remove
// requests, which the web client's useTextChannelMLSCommitListener commits
// from any online member (best effort: nobody online means the leaf stays
// until a later commit). leftActors get a "member_left" timeline line each:
// the sync passes one device per removed person, the device cap passes none.
func (rt *ritualsRuntime) announceRemovals(serverID string, removedMembers, leftActors, textChannels, voiceChannels []string) {
	if len(removedMembers) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), ritualsEffectsTimeout)
	defer cancel()
	removed := append([]string(nil), removedMembers...)
	if rt.hub != nil {
		for _, uid := range leftActors {
			// No acting user exists for a Rituals-side removal, so the timeline
			// entry is "member_left" by the removed person.
			EmitSystemMessage(ctx, rt.pool, rt.hub, serverID, "member_left", uid, nil, "", nil)
		}
		for _, uid := range removed {
			// The WS frame is the kick frame so the device's clients drop the
			// space like after a kick.
			msg, _ := json.Marshal(map[string]interface{}{
				"type":      "member_kicked",
				"server_id": serverID,
				"user_id":   uid,
			})
			rt.hub.BroadcastToServer(serverID, msg)
			rt.broadcastMLSRemovals(ctx, uid, textChannels)
		}
		hub := rt.hub
		channels := append(append([]string(nil), textChannels...), voiceChannels...)
		// Drop the removed device from this server and its channels only, on
		// every connection, without closing any socket: their other Spaces on
		// the same tab stay live (wire contract Item 3, D18).
		time.AfterFunc(500*time.Millisecond, func() {
			for _, uid := range removed {
				hub.DisconnectUserFromServer(uid, serverID, channels)
			}
		})
	}
	if len(voiceChannels) > 0 {
		voice := append([]string(nil), voiceChannels...)
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
			rt.hub.Broadcast(channelID, ritualsRemovalFrame(channelID, userID, deviceID), "")
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
