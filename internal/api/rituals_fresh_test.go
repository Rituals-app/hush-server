package api

// Rituals fork: verifyFresh unit tests (no database). Keys are generated per
// run; nothing here is a real Rituals key.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func ritualsTestSign(t *testing.T, priv ed25519.PrivateKey, prefix, domain string, payload interface{}) string {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, append([]byte(domain), b...))
	enc := base64.RawURLEncoding
	return prefix + enc.EncodeToString(b) + "." + enc.EncodeToString(sig)
}

func TestRitualsVerifyFresh(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	rt := &ritualsRuntime{origin: "https://space.rit.al", pubKey: pub, now: func() time.Time { return now }}
	hex := strings.Repeat("ab", 32)
	pair := map[string]string{"sp": hex, "sub": hex}
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"v": 1, "aud": "https://space.rit.al",
			"pairs": []interface{}{pair, pair},
			"iat":   now.Unix(), "exp": now.Unix() + 60,
		}
	}

	good := ritualsTestSign(t, priv, ritualsFreshPrefix, ritualsFreshDomain, base())
	p, verr := rt.verifyFresh(good)
	if verr != nil || len(p.Pairs) != 2 || p.Pairs[0].Sp != hex {
		t.Fatalf("good token: %v %+v", verr, p)
	}

	cases := map[string]struct {
		token string
		want  *ritualsError
	}{}
	add := func(name string, mut func(m map[string]interface{}), prefix, domain string, want *ritualsError) {
		m := base()
		if mut != nil {
			mut(m)
		}
		cases[name] = struct {
			token string
			want  *ritualsError
		}{ritualsTestSign(t, priv, prefix, domain, m), want}
	}
	add("sync domain", nil, ritualsFreshPrefix, ritualsSyncDomain, errRitualsBadFresh)
	add("ticket prefix", nil, ritualsTicketPrefix, ritualsFreshDomain, errRitualsBadFresh)
	add("lifetime over 60s", func(m map[string]interface{}) { m["exp"] = now.Unix() + 61 }, ritualsFreshPrefix, ritualsFreshDomain, errRitualsBadFresh)
	add("wrong aud", func(m map[string]interface{}) { m["aud"] = "https://space.rituals.app" }, ritualsFreshPrefix, ritualsFreshDomain, errRitualsBadFresh)
	add("missing pairs", func(m map[string]interface{}) { delete(m, "pairs") }, ritualsFreshPrefix, ritualsFreshDomain, errRitualsBadFresh)
	add("bad hex", func(m map[string]interface{}) {
		m["pairs"] = []interface{}{map[string]string{"sp": strings.ToUpper(hex), "sub": hex}}
	}, ritualsFreshPrefix, ritualsFreshDomain, errRitualsBadFresh)
	add("too many pairs", func(m map[string]interface{}) {
		many := make([]interface{}, ritualsMaxFreshPair+1)
		for i := range many {
			many[i] = pair
		}
		m["pairs"] = many
	}, ritualsFreshPrefix, ritualsFreshDomain, errRitualsBadFresh)
	add("expired", func(m map[string]interface{}) {
		m["iat"] = now.Unix() - 200
		m["exp"] = now.Unix() - 150
	}, ritualsFreshPrefix, ritualsFreshDomain, errRitualsFreshExpired)

	for name, c := range cases {
		if _, verr := rt.verifyFresh(c.token); verr != c.want {
			t.Errorf("%s: got %v, want %v", name, verr, c.want)
		}
	}

	// 64 pairs must fit under the token and body limits.
	m := base()
	full := make([]interface{}, ritualsMaxFreshPair)
	for i := range full {
		full[i] = pair
	}
	m["pairs"] = full
	tok := ritualsTestSign(t, priv, ritualsFreshPrefix, ritualsFreshDomain, m)
	if len(tok)+len(`{"token":""}`) > ritualsFreshBodyLimit {
		t.Fatalf("64-pair token is %d bytes, over the body limit", len(tok))
	}
	if _, verr := rt.verifyFresh(tok); verr != nil {
		t.Fatalf("64 pairs: %v", verr)
	}
}
