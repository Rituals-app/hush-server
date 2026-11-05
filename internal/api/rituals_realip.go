package api

import (
	"net/http"
	"net/netip"
	"strings"
)

// RitualsRealIP replaces chi's RealIP middleware in Rituals mode.
//
// chi's RealIP trusts True-Client-IP and X-Real-IP from anyone, so behind our
// Caddy edge (which passes those through) a client could pick its own rate
// limit bucket. Our only ingress is that Caddy container on the same Docker
// network, and Caddy (without trusted_proxies) overwrites X-Forwarded-For with
// the address it accepted the connection from. So:
//   - peer is a private or loopback address (the proxy): use the rightmost
//     X-Forwarded-For entry (what the proxy itself observed);
//   - any other peer: use the peer address and ignore every forwarding header.
//
// RemoteAddr becomes the bare IP (no port), so the per-IP limiters key one
// bucket per client rather than one per TCP connection. This assumes the API
// port is not published to the internet directly (compose: expose only).
func RitualsRealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip, ok := ritualsClientIP(r); ok {
			r.RemoteAddr = ip
		}
		next.ServeHTTP(w, r)
	})
}

func ritualsClientIP(r *http.Request) (string, bool) {
	peer, ok := ritualsParseIP(r.RemoteAddr)
	if !ok {
		return "", false
	}
	if peer.IsLoopback() || peer.IsPrivate() {
		if values := r.Header.Values("X-Forwarded-For"); len(values) > 0 {
			last := values[len(values)-1]
			if i := strings.LastIndexByte(last, ','); i >= 0 {
				last = last[i+1:]
			}
			if ip, ok := ritualsParseIP(strings.TrimSpace(last)); ok {
				return ip.String(), true
			}
		}
	}
	return peer.String(), true
}

// ritualsParseIP accepts "ip", "ip:port", "[v6]" and "[v6]:port".
func ritualsParseIP(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}
