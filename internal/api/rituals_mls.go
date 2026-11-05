package api

// Rituals fork: compare-and-set on the text MLS epoch (wire contract Item 1,
// D1-D7) and the pending MLS remove requests (Item 2, D14-D17).
//
// Only in Rituals mode and only for text groups. A text commit is labelled
// builtOn+1, where builtOn is the epoch in the commit's own MLS framing (or
// the client's parentEpoch when the framing does not parse), and is accepted
// only when no newer epoch is already stored. Two members racing the same
// Remove therefore store exactly one commit; the loser gets 409
// {"error":"epoch_conflict","currentEpoch":N}, catches up and finds the member
// gone. Outside Rituals mode, for voice, and for a legacy commit whose framing
// does not parse and that carries no parentEpoch, the upstream path runs
// unchanged.
//
// Schema (Amendment by Lane E to D5): no numbered migration, no group_type
// column and no unique index. The CAS is serialised by a transaction-scoped
// advisory lock per (channel, "text", ciphersuite), so nothing is built over
// existing rows and startup can never fail on a live database that already
// holds duplicate epochs.

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	ritualsMaxRemoves        = 64
	ritualsMaxDeviceIDLen    = 128
	ritualsPendingTTL        = "30 days"
	ritualsPendingReplayMax  = 256
	ritualsPendingDevicesMax = 64
)

// ritualsCommitEpoch reads the epoch an MLS commit was built on from its
// RFC 9420 MLSMessage framing: version uint16 (= 1, mls10), wire_format
// uint16 (1 public, 2 private), group_id opaque<V> with a QUIC-style varint
// length, then epoch uint64 big-endian. ok is false when the bytes do not
// follow that layout; the caller then falls back to parentEpoch or the
// legacy path. Verified against hush-crypto commits (wire contract R1).
func ritualsCommitEpoch(b []byte) (int64, bool) {
	if len(b) < 4 || binary.BigEndian.Uint16(b[0:2]) != 1 {
		return 0, false
	}
	if wf := binary.BigEndian.Uint16(b[2:4]); wf != 1 && wf != 2 {
		return 0, false
	}
	rest := b[4:]
	n, size, ok := ritualsVarint(rest)
	if !ok || uint64(len(rest)-size) < n {
		return 0, false
	}
	rest = rest[size+int(n):]
	if len(rest) < 8 {
		return 0, false
	}
	epoch := binary.BigEndian.Uint64(rest[:8])
	if epoch > math.MaxInt64-1 {
		return 0, false
	}
	return int64(epoch), true
}

// ritualsVarint decodes an RFC 9000 style variable-length integer limited to
// the 1, 2 and 4 byte forms MLS allows (prefix 11 is invalid in MLS).
func ritualsVarint(b []byte) (value uint64, size int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0] & 0x3f), 1, true
	case 1:
		if len(b) < 2 {
			return 0, 0, false
		}
		return uint64(binary.BigEndian.Uint16(b[:2]) & 0x3fff), 2, true
	case 2:
		if len(b) < 4 {
			return 0, 0, false
		}
		return uint64(binary.BigEndian.Uint32(b[:4]) & 0x3fffffff), 4, true
	}
	return 0, 0, false
}

// ritualsRemoveHint names one leaf a Remove commit removes: exactly the
// requester_id / requester_device_id pair of an mls.add_request frame.
type ritualsRemoveHint struct {
	UserID   string `json:"userId"`
	DeviceID string `json:"deviceId"`
}

// ritualsParseRemoves validates the optional removes hint. nil raw means no
// hint; a malformed list or more than 64 entries is bad_removes.
func ritualsParseRemoves(raw json.RawMessage) (users, devices []string, ok bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil, true
	}
	var hints []ritualsRemoveHint
	if err := json.Unmarshal(raw, &hints); err != nil || len(hints) > ritualsMaxRemoves {
		return nil, nil, false
	}
	for _, h := range hints {
		u, err := uuid.Parse(h.UserID)
		if err != nil || h.DeviceID == "" || len(h.DeviceID) > ritualsMaxDeviceIDLen {
			return nil, nil, false
		}
		users = append(users, u.String())
		devices = append(devices, h.DeviceID)
	}
	return users, devices, true
}

// ritualsEpochLockKey is the advisory lock text for one text group.
func ritualsEpochLockKey(channelID string, ciphersuite int) string {
	return channelID + ":text:" + strconv.Itoa(ciphersuite)
}

// ritualsTextHeadSQL is the newest stored text epoch: the larger of the
// group info epoch and the newest commit label. mls_commits has no
// group_type column; voice groups live on voice channel ids, so every commit
// row of a text channel is a text commit. Indexes: mls_group_info's unique
// (channel_id, group_type, ciphersuite) and idx_mls_commits_channel_epoch
// (channel_id, ciphersuite, epoch).
const ritualsTextHeadSQL = `
SELECT GREATEST(
	COALESCE((SELECT epoch FROM mls_group_info
	          WHERE channel_id = $1 AND group_type = 'text' AND ciphersuite = $2), 0),
	COALESCE((SELECT MAX(epoch) FROM mls_commits
	          WHERE channel_id = $1 AND ciphersuite = $2), 0))`

// ritualsTextGroupInfoSQL upserts text group info only forward: an older
// epoch never overwrites a newer one (D6).
const ritualsTextGroupInfoSQL = `
INSERT INTO mls_group_info (channel_id, group_type, group_info_bytes, epoch, ciphersuite, updated_at)
VALUES ($1, 'text', $2, $3, $4, now())
ON CONFLICT (channel_id, group_type, ciphersuite) WHERE channel_id IS NOT NULL
DO UPDATE SET group_info_bytes = EXCLUDED.group_info_bytes,
              epoch = EXCLUDED.epoch,
              updated_at = now()
WHERE mls_group_info.epoch <= EXCLUDED.epoch`

// ritualsTextCommitActive reports whether a text commit or group info write
// on this request goes through the Rituals CAS.
func ritualsTextCommitActive(groupType string) *ritualsRuntime {
	if groupType != "text" {
		return nil
	}
	rt := ritualsActive()
	if rt == nil || rt.pool == nil {
		return nil
	}
	return rt
}

// putTextGroupInfo is the Rituals text PUT: monotonic, and the caller replies
// 204 whether or not the guard skipped the write.
func (rt *ritualsRuntime) putTextGroupInfo(ctx context.Context, channelID string, groupInfo []byte, epoch int64, ciphersuite int) error {
	_, err := rt.pool.Exec(ctx, ritualsTextGroupInfoSQL, channelID, groupInfo, epoch, ciphersuite)
	return err
}

// postTextCommit runs the CAS for one text commit and writes the reply.
// It returns false, having written nothing, only for the legacy path (the
// framing does not parse and no parentEpoch was sent); the caller then runs
// the upstream code unchanged.
func (rt *ritualsRuntime) postTextCommit(w http.ResponseWriter, r *http.Request, broadcast func(channelID string, message []byte, excludeClientID string),
	channelID, userID, deviceID string, req *postCommitRequest, commitBytes []byte) bool {
	parsed, ok := ritualsCommitEpoch(commitBytes)
	var builtOn int64
	switch {
	case ok:
		// The framing is authoritative; parentEpoch is only a floor. A join
		// sends parentEpoch = the stored info label, and an old client's
		// Remove left label N on bytes at N+1, so the framing may be ahead
		// of parentEpoch: that join is accepted at framing+1 and its info
		// heals the row (review M1). A framing behind parentEpoch is malformed.
		if req.ParentEpoch != nil && parsed < *req.ParentEpoch {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parent_epoch_mismatch"})
			return true
		}
		builtOn = parsed
	case req.ParentEpoch != nil:
		builtOn = *req.ParentEpoch
	default:
		return false
	}
	if req.ParentEpoch != nil && req.GroupInfo == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group_info_required"})
		return true
	}
	// req.Epoch is checked against what the client says it built on
	// (parentEpoch+1 for a new client), and the label comes from builtOn.
	claimed := builtOn
	if req.ParentEpoch != nil {
		claimed = *req.ParentEpoch
	}
	if builtOn < 0 || builtOn > math.MaxInt64-1 || claimed < 0 || claimed > math.MaxInt64-1 ||
		(req.Epoch != claimed && req.Epoch != claimed+1) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_epoch"})
		return true
	}
	removeUsers, removeDevices, ok := ritualsParseRemoves(req.Removes)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_removes"})
		return true
	}
	var groupInfo []byte
	if req.GroupInfo != "" {
		gi, err := base64.StdEncoding.DecodeString(req.GroupInfo)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid groupInfo base64"})
			return true
		}
		groupInfo = gi
	}
	label := builtOn + 1

	ctx := r.Context()
	head, accepted, err := rt.casTextCommit(ctx, channelID, userID, req.Ciphersuite, builtOn, label, commitBytes, groupInfo)
	if err != nil {
		slog.Error("rituals mls: text commit", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store commit"})
		return true
	}
	if !accepted {
		writeJSON(w, http.StatusConflict, map[string]interface{}{"error": "epoch_conflict", "currentEpoch": head})
		return true
	}

	if len(removeUsers) > 0 {
		if _, err := rt.pool.Exec(ctx, `
			DELETE FROM rituals.pending_mls_removals
			WHERE channel_id = $1
			  AND (user_id, device_id) IN (SELECT * FROM unnest($2::uuid[], $3::text[]))`,
			channelID, removeUsers, removeDevices); err != nil {
			// The record expires by TTL; nothing that names a member is logged.
			slog.Error("rituals mls: clear pending removals", "err", err)
		}
	}

	msg, _ := json.Marshal(map[string]interface{}{
		"type":             "mls.commit",
		"channel_id":       channelID,
		"epoch":            label,
		"commit_bytes":     req.CommitBytes,
		"sender_id":        userID,
		"sender_device_id": deviceID,
		"group_type":       "text",
	})
	broadcast(channelID, msg, "")
	w.WriteHeader(http.StatusNoContent)
	return true
}

// casTextCommit stores the commit at label when builtOn is not behind the
// stored head. It returns the head and whether the commit was stored.
func (rt *ritualsRuntime) casTextCommit(ctx context.Context, channelID, userID string, ciphersuite int, builtOn, label int64,
	commitBytes, groupInfo []byte) (int64, bool, error) {
	tx, err := rt.pool.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		ritualsEpochLockKey(channelID, ciphersuite)); err != nil {
		return 0, false, err
	}
	var head int64
	if err := tx.QueryRow(ctx, ritualsTextHeadSQL, channelID, ciphersuite).Scan(&head); err != nil {
		return 0, false, err
	}
	if builtOn < head {
		return head, false, nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO mls_commits (channel_id, epoch, commit_bytes, sender_id, ciphersuite)
		VALUES ($1, $2, $3, $4, $5)`, channelID, label, commitBytes, userID, ciphersuite); err != nil {
		return 0, false, err
	}
	if len(groupInfo) > 0 {
		if _, err := tx.Exec(ctx, ritualsTextGroupInfoSQL, channelID, groupInfo, label, ciphersuite); err != nil {
			return 0, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, false, err
	}
	return label, true, nil
}

// ritualsRemovalFrame is byte-identical to the live frame broadcastMLSRemovals
// sends, so a replay and a live request are indistinguishable.
func ritualsRemovalFrame(channelID, userID, deviceID string) []byte {
	b, _ := json.Marshal(map[string]string{
		"type":                "mls.add_request",
		"channel_id":          channelID,
		"action":              "remove",
		"requester_id":        userID,
		"requester_device_id": deviceID,
	})
	return b
}

// recordPendingRemovals stores one pending remove request per removed user,
// text channel and MLS device (at most 64 devices per user), inside the sync
// transaction, and drops records past the 30-day TTL.
func ritualsRecordPendingRemovals(ctx context.Context, tx pgx.Tx, textChannels, userIDs []string) error {
	if len(textChannels) > 0 && len(userIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO rituals.pending_mls_removals (channel_id, user_id, device_id)
			SELECT ch, u, d.device_id
			FROM unnest($1::uuid[]) AS ch
			CROSS JOIN unnest($2::uuid[]) AS u
			CROSS JOIN LATERAL (
				SELECT device_id FROM mls_credentials WHERE user_id = u
				ORDER BY device_id LIMIT `+strconv.Itoa(ritualsPendingDevicesMax)+`
			) d
			ON CONFLICT (channel_id, user_id, device_id) DO UPDATE SET created_at = now()`,
			textChannels, userIDs); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `DELETE FROM rituals.pending_mls_removals
		WHERE created_at < now() - interval '`+ritualsPendingTTL+`'`)
	return err
}

// ritualsClearPendingForSeat drops pending removals of a user re-seated in
// a server, inside the claim transaction, so a re-added member is not
// removed again by a stale replay.
func ritualsClearPendingForSeat(ctx context.Context, tx pgx.Tx, userID, serverID string) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM rituals.pending_mls_removals
		WHERE user_id = $1
		  AND channel_id IN (SELECT id FROM channels WHERE server_id = $2)`, userID, serverID)
	return err
}

// pendingRemovalFrames is the subscribe hook: the stored remove requests for
// channelID that do not name the subscriber, oldest first. Errors return
// nothing; the next subscribe tries again.
func (rt *ritualsRuntime) pendingRemovalFrames(ctx context.Context, channelID, userID string) [][]byte {
	if _, err := uuid.Parse(channelID); err != nil {
		return nil
	}
	if _, err := uuid.Parse(userID); err != nil {
		return nil
	}
	rows, err := rt.pool.Query(ctx, `
		SELECT user_id::text, device_id FROM rituals.pending_mls_removals
		WHERE channel_id = $1
		  AND created_at > now() - interval '`+ritualsPendingTTL+`'
		  AND user_id <> $2
		ORDER BY created_at, user_id, device_id
		LIMIT `+strconv.Itoa(ritualsPendingReplayMax), channelID, userID)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			slog.Error("rituals mls: pending removals", "err", err)
		}
		return nil
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var uid, device string
		if err := rows.Scan(&uid, &device); err != nil {
			slog.Error("rituals mls: pending removals", "err", err)
			return nil
		}
		out = append(out, ritualsRemovalFrame(channelID, uid, device))
	}
	if rows.Err() != nil {
		slog.Error("rituals mls: pending removals", "err", rows.Err())
		return nil
	}
	return out
}
