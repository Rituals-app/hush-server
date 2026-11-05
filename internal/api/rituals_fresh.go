package api

// Rituals fork: POST /api/rituals/spaces/fresh {"token":"rtf1..."}.
//
// Server to server from the Rituals API: the signed token is the auth, as for
// /spaces/sync. Rituals learns one content-free boolean per (sp, sub) pair:
// is there a text message, from someone other than that person, newer than
// what that person has read, in that space? Never a count, never who, never
// what. 200 {"fresh":[bool, ...]} in input order; 400 bad_fresh,
// 403 fresh_expired.
//
// Per pair, U = every Hush user seated under (sp, sub) in rituals.seats (one
// per device until device linking lands). fresh = EXISTS a message in a
// type='text' channel of the space whose recipient_id is NULL or in U, whose
// sender_id is NULL (a federated sender: someone else) or not in U, and whose
// "timestamp" is after MAX(read_markers.read_up_to_ts) over U for that channel
// (no marker: any such message counts). An unknown space or an unclaimed
// (sp, sub) pair is false. Rate limiting: its own per-IP bucket (5/s, burst
// 60), outside the global limiter like /spaces/sync; the Rituals API caches,
// coalesces and caps its own calls (4 reads a second).

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

const ritualsFreshBodyLimit = 16 << 10

// ritualsFreshSQL is one parameterised statement bounded by the 64-pair limit.
// Columns (migrations 000001, 000002, 000007, 000010, 000023, 000030):
// channels(id, server_id, type), messages(channel_id, sender_id NULLable,
// recipient_id NULLable, "timestamp"), read_markers(channel_id, user_id,
// read_up_to_ts NULLable); rituals.spaces(sp, server_id) and
// rituals.seats(sp, sub, user_id) from rituals.go.
const ritualsFreshSQL = `
SELECT p.ord, (seat.u IS NOT NULL AND EXISTS (
	SELECT 1
	FROM rituals.spaces s
	JOIN channels c ON c.server_id = s.server_id AND c.type = 'text'
	JOIN messages m ON m.channel_id = c.id
	WHERE s.sp = p.sp
	  AND (m.recipient_id IS NULL OR m.recipient_id = ANY(seat.u))
	  AND (m.sender_id IS NULL OR NOT (m.sender_id = ANY(seat.u)))
	  AND m."timestamp" > COALESCE(
	      (SELECT MAX(rm.read_up_to_ts) FROM read_markers rm
	       WHERE rm.channel_id = c.id AND rm.user_id = ANY(seat.u)),
	      '-infinity'::timestamptz)
)) AS fresh
FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS p(sp, sub, ord)
CROSS JOIN LATERAL (
	SELECT array_agg(se.user_id) AS u
	FROM rituals.seats se
	WHERE se.sp = p.sp AND se.sub = p.sub
) seat
ORDER BY p.ord`

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
	fresh, err := rt.queryFresh(r, p.Pairs)
	if err != nil {
		slog.Error("rituals fresh", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fresh_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]bool{"fresh": fresh})
}

func (rt *ritualsRuntime) queryFresh(r *http.Request, pairs []ritualsFreshPair) ([]bool, error) {
	out := make([]bool, len(pairs))
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
		var fresh bool
		if err := rows.Scan(&ord, &fresh); err != nil {
			return nil, err
		}
		if ord >= 1 && ord <= int64(len(out)) {
			out[ord-1] = fresh
		}
	}
	return out, rows.Err()
}
