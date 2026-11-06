package api

// Rituals fork: the per-Space person key. Several Hush users (devices) can
// hold seats for one Rituals person (sub) in a space; the person key lets
// clients show them as one person. It is derived here only, at read time,
// from the seat's sub and the space's sp, so it is stable per Space and
// person, differs across Spaces and reveals neither sub nor any account id.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/google/uuid"

	"github.com/hushhq/hush-server/internal/models"
)

const ritualsPersonKeyLabel = "rituals person key v1"

// ritualsPersonKeySecret derives the person key secret from the server's
// JWT secret, so no new setting is needed. Empty input gives nil (no keys).
func ritualsPersonKeySecret(jwtSecret string) []byte {
	if jwtSecret == "" {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte(ritualsPersonKeyLabel))
	return mac.Sum(nil)
}

// personKey returns the opaque key for (sp, sub), or "" without a secret.
func (rt *ritualsRuntime) personKey(sp, sub string) string {
	if len(rt.personSecret) == 0 || sp == "" || sub == "" {
		return ""
	}
	mac := hmac.New(sha256.New, rt.personSecret)
	mac.Write([]byte(sp))
	mac.Write([]byte{0})
	mac.Write([]byte(sub))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// ritualsAnnotateMembers fills PersonKey for seated members of a Rituals
// space. Outside RITUALS_MODE, for other guilds, or on error it leaves the
// list as it is (the field stays absent).
func ritualsAnnotateMembers(ctx context.Context, serverID string, members []models.ServerMemberWithUser) {
	rt := ritualsActive()
	if rt == nil || len(rt.personSecret) == 0 || len(members) == 0 {
		return
	}
	if _, err := uuid.Parse(serverID); err != nil {
		return
	}
	rows, err := rt.pool.Query(ctx, `
		SELECT s.user_id::text, s.sp, s.sub
		FROM rituals.seats s JOIN rituals.spaces sp ON sp.sp = s.sp
		WHERE sp.server_id = $1`, serverID)
	if err != nil {
		return
	}
	defer rows.Close()
	keys := map[string]string{}
	for rows.Next() {
		var userID, sp, sub string
		if err := rows.Scan(&userID, &sp, &sub); err != nil {
			return
		}
		keys[userID] = rt.personKey(sp, sub)
	}
	if rows.Err() != nil {
		return
	}
	for i := range members {
		members[i].PersonKey = keys[members[i].ID]
	}
}
