package api

// Rituals fork: POST /api/rituals/spaces/fresh {"token":"rtf1..."}.
//
// Server to server from the Rituals API: the signed token is the auth, as for
// /spaces/sync. Rituals learns one content-free mark per (sp, sub) pair: an
// opaque 32-hex digest of the newest text message in that space that someone
// other than that person sent, or "". Rituals compares it with the mark it
// stored when that person last opened the Space (its own "seen" record), so
// no read state, timestamp, sender or count ever leaves this server.
// 200 {"marks":[string, ...]} in input order; 400 bad_fresh, 403 fresh_expired,
// 500 fresh_failed.
//
// Per pair, U = every Hush user seated under (sp, sub) in rituals.seats (one
// per device identity). The newest qualifying message is the row with the
// largest ("timestamp", id) in a type='text' channel of the space whose
// recipient_id is NULL or in U and whose sender_id is NULL (a federated
// sender: someone else) or not in U. System messages live in system_messages
// and never count. mark = lowercase hex(SHA-256("rituals-space-mark-v1" ||
// 0x00 || m.id::text))[0:32]. An unknown space, an unclaimed (sp, sub) pair or
// no qualifying message gives "". Rate limiting: its own per-IP bucket (5/s,
// burst 60), outside the global limiter like /spaces/sync; the Rituals API
// caches, coalesces and caps its own calls.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
)

const (
	ritualsFreshBodyLimit = 16 << 10
	ritualsMarkTag        = "rituals-space-mark-v1"
	ritualsMarkHexLen     = 32
)

// ritualsFreshSQL is one parameterised statement bounded by the 64-pair limit.
// For each text channel of the space the inner lateral takes the newest
// qualifying row with a backward scan of idx_messages_channel_timestamp
// (channel_id, "timestamp"), so the work per channel stops at the first row
// not sent by this sub's seats; the outer lateral picks the newest of those.
// Columns (migrations 000001, 000002, 000007, 000023): channels(id, server_id,
// type), messages(id, channel_id, sender_id NULLable, recipient_id NULLable,
// "timestamp"); rituals.spaces(sp, server_id) and rituals.seats(sp, sub,
// user_id) from rituals.go.
const ritualsFreshSQL = `
SELECT p.ord, latest.id
FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS p(sp, sub, ord)
CROSS JOIN LATERAL (
	SELECT array_agg(se.user_id) AS u
	FROM rituals.seats se
	WHERE se.sp = p.sp AND se.sub = p.sub
) seat
LEFT JOIN LATERAL (
	SELECT cm.id::text AS id
	FROM rituals.spaces s
	JOIN channels c ON c.server_id = s.server_id AND c.type = 'text'
	CROSS JOIN LATERAL (
		SELECT m.id, m."timestamp"
		FROM messages m
		WHERE m.channel_id = c.id
		  AND (m.recipient_id IS NULL OR m.recipient_id = ANY(seat.u))
		  AND (m.sender_id IS NULL OR NOT (m.sender_id = ANY(seat.u)))
		ORDER BY m."timestamp" DESC, m.id DESC
		LIMIT 1
	) cm
	WHERE s.sp = p.sp AND seat.u IS NOT NULL
	ORDER BY cm."timestamp" DESC, cm.id DESC
	LIMIT 1
) latest ON true
ORDER BY p.ord`

// ritualsMark is the mark of one message id as Postgres prints uuid::text.
func ritualsMark(messageID string) string {
	h := sha256.New()
	h.Write([]byte(ritualsMarkTag))
	h.Write([]byte{0})
	h.Write([]byte(messageID))
	return hex.EncodeToString(h.Sum(nil))[:ritualsMarkHexLen]
}

func (rt *ritualsRuntime) handleFresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, ritualsFreshBodyLimit)).Decode(&req); err != nil {
		writeRitualsError(w, errRitualsBadFresh)
		return
	}
	p, verr := rt.verifyFresh(req.Token)
	if verr != nil {
		writeRitualsError(w, verr)
		return
	}
	marks, err := rt.queryMarks(r, p.Pairs)
	if err != nil {
		// The error never carries a row: no id, sender or space is logged.
		slog.Error("rituals fresh", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fresh_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"marks": marks})
}

func (rt *ritualsRuntime) queryMarks(r *http.Request, pairs []ritualsFreshPair) ([]string, error) {
	out := make([]string, len(pairs))
	if len(pairs) == 0 {
		return out, nil
	}
	sps := make([]string, len(pairs))
	subs := make([]string, len(pairs))
	for i, pair := range pairs {
		sps[i], subs[i] = pair.Sp, pair.Sub
	}
	rows, err := rt.pool.Query(r.Context(), ritualsFreshSQL, sps, subs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ord int64
		var id *string
		if err := rows.Scan(&ord, &id); err != nil {
			return nil, err
		}
		if ord >= 1 && ord <= int64(len(out)) && id != nil {
			out[ord-1] = ritualsMark(*id)
		}
	}
	return out, rows.Err()
}
