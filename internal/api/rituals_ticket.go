package api

// Rituals fork: verification of the two signed formats from the integration
// contract (sections 2 and 3).
//
//   ticket = "rt1."  + B64URL(payload) + "." + B64URL(Ed25519(key, "rituals-space-ticket-v1\n" || payload))
//   sync   = "rts1." + B64URL(payload) + "." + B64URL(Ed25519(key, "rituals-space-sync-v1\n" || payload))
//
// B64URL is base64url without padding; anything outside that alphabet
// (padding, whitespace, newlines) is rejected before decoding.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	ritualsTicketPrefix = "rt1."
	ritualsSyncPrefix   = "rts1."
	ritualsTicketDomain = "rituals-space-ticket-v1\n"
	ritualsSyncDomain   = "rituals-space-sync-v1\n"
	ritualsTicketMaxLen = 2048
	ritualsSyncMaxLen   = 8192
	ritualsExpLeeway    = 30   // seconds a ticket is still accepted after exp
	ritualsIatSkew      = 60   // seconds iat may run ahead of our clock
	ritualsMaxLifetime  = 3600 // largest accepted exp - iat
	ritualsMaxSyncSubs  = 32
)

type ritualsError struct {
	status int
	code   string
}

func (e *ritualsError) Error() string { return e.code }

var (
	errRitualsBadTicket     = &ritualsError{http.StatusBadRequest, "bad_ticket"}
	errRitualsTicketExpired = &ritualsError{http.StatusForbidden, "ticket_expired"}
	errRitualsBadSync       = &ritualsError{http.StatusBadRequest, "bad_sync"}
	errRitualsSyncExpired   = &ritualsError{http.StatusForbidden, "sync_expired"}
)

func writeRitualsError(w http.ResponseWriter, e *ritualsError) {
	writeJSON(w, e.status, map[string]string{"error": e.code})
}

var (
	ritualsHex64    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ritualsHex32    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	ritualsUsername = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)
)

// ritualsTicket is the rt1 payload.
type ritualsTicket struct {
	V    int     `json:"v"`
	Aud  string  `json:"aud"`
	Sp   string  `json:"sp"`
	Sub  string  `json:"sub"`
	Role string  `json:"role"`
	Name string  `json:"name"`
	Dn   string  `json:"dn"`
	Un   *string `json:"un"`
	Iat  int64   `json:"iat"`
	Exp  int64   `json:"exp"`
	Jti  string  `json:"jti"`
}

// ritualsSync is the rts1 payload.
type ritualsSync struct {
	V    int      `json:"v"`
	Aud  string   `json:"aud"`
	Sp   string   `json:"sp"`
	Subs []string `json:"subs"`
	Name *string  `json:"name"`
	Iat  int64    `json:"iat"`
	Exp  int64    `json:"exp"`
}

func decodeRitualsB64(s string) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return nil, false
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// openRitualsSigned checks "<prefix><payload>.<sig>" (exactly three
// dot-separated parts) and the Ed25519 signature over domain || payload,
// and returns the payload bytes.
func openRitualsSigned(pub ed25519.PublicKey, s, prefix, domain string, maxLen int) ([]byte, bool) {
	if len(pub) != ed25519.PublicKeySize || len(s) > maxLen || !strings.HasPrefix(s, prefix) {
		return nil, false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, ok := decodeRitualsB64(parts[1])
	if !ok {
		return nil, false
	}
	sig, ok := decodeRitualsB64(parts[2])
	if !ok || len(sig) != ed25519.SignatureSize {
		return nil, false
	}
	msg := make([]byte, 0, len(domain)+len(payload))
	msg = append(msg, domain...)
	msg = append(msg, payload...)
	if !ed25519.Verify(pub, msg, sig) {
		return nil, false
	}
	return payload, true
}

func ritualsCodePoints(s string, lo, hi int) bool {
	if !utf8.ValidString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	return n >= lo && n <= hi
}

type ritualsWindowResult int

const (
	ritualsWindowOK ritualsWindowResult = iota
	ritualsWindowBad
	ritualsWindowExpired
)

// ritualsWindow applies the contract's time checks: now <= exp+30,
// iat <= now+60, exp-iat <= 3600 (and exp after iat).
func ritualsWindow(iat, exp, now int64) ritualsWindowResult {
	if iat <= 0 || exp <= iat || exp-iat > ritualsMaxLifetime || iat > now+ritualsIatSkew {
		return ritualsWindowBad
	}
	if now > exp+ritualsExpLeeway {
		return ritualsWindowExpired
	}
	return ritualsWindowOK
}

// verifyTicket returns the verified rt1 payload, or bad_ticket (400) /
// ticket_expired (403). Expiry is only reported for authentic tickets.
func (rt *ritualsRuntime) verifyTicket(s string) (*ritualsTicket, *ritualsError) {
	payload, ok := openRitualsSigned(rt.pubKey, s, ritualsTicketPrefix, ritualsTicketDomain, ritualsTicketMaxLen)
	if !ok {
		return nil, errRitualsBadTicket
	}
	var t ritualsTicket
	if err := json.Unmarshal(payload, &t); err != nil {
		return nil, errRitualsBadTicket
	}
	if t.V != 1 || t.Aud != rt.origin ||
		!ritualsHex64.MatchString(t.Sp) || !ritualsHex64.MatchString(t.Sub) ||
		(t.Role != "owner" && t.Role != "member") ||
		!ritualsCodePoints(t.Name, 1, 100) || !ritualsCodePoints(t.Dn, 1, 64) ||
		(t.Un != nil && !ritualsUsername.MatchString(*t.Un)) ||
		!ritualsHex32.MatchString(t.Jti) {
		return nil, errRitualsBadTicket
	}
	switch ritualsWindow(t.Iat, t.Exp, rt.now().Unix()) {
	case ritualsWindowBad:
		return nil, errRitualsBadTicket
	case ritualsWindowExpired:
		return nil, errRitualsTicketExpired
	}
	return &t, nil
}

// verifySync returns the verified rts1 payload, or bad_sync (400) /
// sync_expired (403).
func (rt *ritualsRuntime) verifySync(s string) (*ritualsSync, *ritualsError) {
	payload, ok := openRitualsSigned(rt.pubKey, s, ritualsSyncPrefix, ritualsSyncDomain, ritualsSyncMaxLen)
	if !ok {
		return nil, errRitualsBadSync
	}
	var p ritualsSync
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, errRitualsBadSync
	}
	// subs is required (an empty array is valid: nobody may stay).
	if p.V != 1 || p.Aud != rt.origin || !ritualsHex64.MatchString(p.Sp) ||
		p.Subs == nil || len(p.Subs) > ritualsMaxSyncSubs ||
		(p.Name != nil && !ritualsCodePoints(*p.Name, 1, 100)) {
		return nil, errRitualsBadSync
	}
	for _, sub := range p.Subs {
		if !ritualsHex64.MatchString(sub) {
			return nil, errRitualsBadSync
		}
	}
	switch ritualsWindow(p.Iat, p.Exp, rt.now().Unix()) {
	case ritualsWindowBad:
		return nil, errRitualsBadSync
	case ritualsWindowExpired:
		return nil, errRitualsSyncExpired
	}
	return &p, nil
}
