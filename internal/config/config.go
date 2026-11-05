package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds environment-based configuration for the Hush API.
type Config struct {
	Port                     int
	DatabaseURL              string
	JWTSecret                string
	JWTExpiry                time.Duration
	CORSOrigin               string
	WSAllowedOrigins         []string
	Production               bool
	AdminBootstrapSecret     string
	AdminSessionTTL          time.Duration
	ServiceIdentityMasterKey string
	LiveKitAPIKey            string
	LiveKitAPISecret         string
	LiveKitURL               string
	LiveKitPublicURL         string
	// TransparencyLogPrivateKey is the hex-encoded 32-byte Ed25519 seed for the
	// transparency log signing keypair. If empty in dev mode, an ephemeral key
	// is generated with a warning. Required in production.
	TransparencyLogPrivateKey string
	// GiphyAPIKey is the Giphy v1 API key. When empty the
	// /api/gif/search route returns 503 — the chat surface keeps
	// working, just without the GIF picker.
	GiphyAPIKey string

	// Rituals fork (see internal/api/rituals.go). RitualsMode turns on the
	// Rituals Spaces routes, the signed-ticket registration gate, the
	// startup instance policy and the extra hardening. When it is on, the
	// ticket public key is required (base64url, no padding, 32 bytes).
	RitualsMode            bool
	RitualsSpaceOrigin     string
	RitualsTicketPublicKey string
}

// Load reads configuration from environment variables.
func Load() Config {
	port := 8080
	if p := os.Getenv("PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	jwtExpiryHours := 168 // 7 days
	if h := os.Getenv("JWT_EXPIRY_HOURS"); h != "" {
		if v, err := strconv.Atoi(h); err == nil && v > 0 {
			jwtExpiryHours = v
		}
	}
	adminSessionTTLHours := 24
	if h := os.Getenv("ADMIN_SESSION_TTL_HOURS"); h != "" {
		if v, err := strconv.Atoi(h); err == nil && v > 0 {
			adminSessionTTLHours = v
		}
	}
	prod := os.Getenv("PRODUCTION")
	production := prod == "1" || prod == "true" || prod == "yes"

	corsOrigin := os.Getenv("CORS_ORIGIN")
	if corsOrigin == "" {
		if domain := os.Getenv("DOMAIN"); domain != "" {
			corsOrigin = "https://" + domain
		}
	}

	rm := strings.ToLower(strings.TrimSpace(os.Getenv("RITUALS_MODE")))
	ritualsMode := rm == "1" || rm == "true" || rm == "yes"
	ritualsOrigin := strings.TrimRight(strings.TrimSpace(os.Getenv("RITUALS_SPACE_ORIGIN")), "/")
	if ritualsMode && ritualsOrigin == "" {
		ritualsOrigin = "https://space.rit.al"
	}

	return Config{
		Port:                      port,
		DatabaseURL:               os.Getenv("DATABASE_URL"),
		JWTSecret:                 os.Getenv("JWT_SECRET"),
		JWTExpiry:                 time.Duration(jwtExpiryHours) * time.Hour,
		CORSOrigin:                corsOrigin,
		WSAllowedOrigins:          parseCSV(os.Getenv("WS_ALLOWED_ORIGINS")),
		Production:                production,
		AdminBootstrapSecret:      os.Getenv("ADMIN_BOOTSTRAP_SECRET"),
		AdminSessionTTL:           time.Duration(adminSessionTTLHours) * time.Hour,
		ServiceIdentityMasterKey:  os.Getenv("SERVICE_IDENTITY_MASTER_KEY"),
		LiveKitAPIKey:             os.Getenv("LIVEKIT_API_KEY"),
		LiveKitAPISecret:          os.Getenv("LIVEKIT_API_SECRET"),
		LiveKitURL:                os.Getenv("LIVEKIT_URL"),
		LiveKitPublicURL:          os.Getenv("LIVEKIT_PUBLIC_URL"),
		TransparencyLogPrivateKey: os.Getenv("TRANSPARENCY_LOG_PRIVATE_KEY"),
		GiphyAPIKey:               os.Getenv("GIPHY_API_KEY"),
		RitualsMode:               ritualsMode,
		RitualsSpaceOrigin:        ritualsOrigin,
		RitualsTicketPublicKey:    strings.TrimSpace(os.Getenv("RITUALS_TICKET_PUBLIC_KEY")),
	}
}

func parseCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}
