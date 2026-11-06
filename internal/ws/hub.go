package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"sync"

	"github.com/gorilla/websocket"
)

// Hub holds all connected clients, channel subscriptions, and guild subscriptions.
type Hub struct {
	mu       sync.RWMutex
	clients  map[string]*Client            // clientID -> client
	channels map[string]map[string]*Client // channelID -> clientID -> client
	servers  map[string]map[string]*Client // serverID -> clientID -> client
	presence map[string]struct{}           // userID -> present

	// Rituals fork: called after an accepted channel subscribe; the frames
	// it returns go to that client only (see SetSubscribeHook).
	subscribeHook func(ctx context.Context, channelID, userID string) [][]byte
	// Rituals fork: called outside h.mu after a local user's connection
	// subscribes to, unsubscribes from or disconnects while subscribed to
	// servers (see SetServerActivityHook).
	serverActivityHook func(userID string, serverIDs []string)
}

// NewHub creates a new Hub.
func NewHub() *Hub {
	return &Hub{
		clients:  make(map[string]*Client),
		channels: make(map[string]map[string]*Client),
		servers:  make(map[string]map[string]*Client),
		presence: make(map[string]struct{}),
	}
}

// Register adds a client. Caller must ensure client has valid userID.
// Federated clients use "fed:<federatedIdentityID>" as their presence key to
// avoid collisions with local user IDs.
func (h *Hub) Register(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c.id] = c
	if c.federatedIdentityID != "" {
		h.presence["fed:"+c.federatedIdentityID] = struct{}{}
	} else {
		h.presence[c.userID] = struct{}{}
	}
	// A new connection shares no server yet: only its own list changes.
	h.refreshPresenceLocked([]*Client{c})
}

// Unregister removes a client and broadcasts presence update.
// Only removes from presence if no other client shares the same identity.
//
// Rituals fork: the servers c was subscribed to are reported to the server
// activity hook after the lock is released.
func (h *Hub) Unregister(c *Client) {
	if left, ok := h.unregister(c); ok {
		h.noteServerActivity(c, left)
	}
}

// unregister is Unregister under h.mu, released by defer so a panic in a
// send (a peer whose send channel its read pump already closed) can never
// leave the hub locked. It returns the servers c was subscribed to.
func (h *Hub) unregister(c *Client) ([]string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c.id]; !ok {
		return nil, false
	}
	left := make([]string, 0, len(c.servers))
	for serverID := range c.servers {
		left = append(left, serverID)
	}
	sort.Strings(left)
	peers := h.serverPeersLocked(c)
	delete(h.clients, c.id)
	for _, m := range h.channels {
		delete(m, c.id)
	}
	for _, m := range h.servers {
		delete(m, c.id)
	}
	if c.federatedIdentityID != "" {
		if !h.hasOtherClientForFederatedUser(c.federatedIdentityID) {
			delete(h.presence, "fed:"+c.federatedIdentityID)
		}
	} else {
		if !h.hasOtherClientForUser(c.userID) {
			delete(h.presence, c.userID)
		}
	}
	c.servers = nil
	h.refreshPresenceLocked(peers)
	return left, true
}

// hasOtherClientForUser returns true if any remaining client belongs to the given userID.
// Must be called with h.mu held.
func (h *Hub) hasOtherClientForUser(userID string) bool {
	for _, client := range h.clients {
		if client.userID == userID {
			return true
		}
	}
	return false
}

// hasOtherClientForFederatedUser returns true if any remaining client belongs
// to the given federated identity ID. Must be called with h.mu held.
func (h *Hub) hasOtherClientForFederatedUser(federatedID string) bool {
	for _, client := range h.clients {
		if client.federatedIdentityID == federatedID {
			return true
		}
	}
	return false
}

// Subscribe adds the client to the channel.
func (h *Hub) Subscribe(c *Client, channelID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.channels[channelID] == nil {
		h.channels[channelID] = make(map[string]*Client)
	}
	h.channels[channelID][c.id] = c
}

// Unsubscribe removes the client from the channel.
func (h *Hub) Unsubscribe(c *Client, channelID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m := h.channels[channelID]; m != nil {
		delete(m, c.id)
		if len(m) == 0 {
			delete(h.channels, channelID)
		}
	}
}

// SubscribeToServer adds the client to the server's subscriber set.
// Rituals fork: then reports serverID to the server activity hook, outside
// the lock.
func (h *Hub) SubscribeToServer(c *Client, serverID string) {
	h.subscribeToServer(c, serverID)
	h.noteServerActivity(c, []string{serverID})
}

// subscribeToServer is SubscribeToServer under h.mu (released by defer, as in
// unregister).
func (h *Hub) subscribeToServer(c *Client, serverID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.servers[serverID] == nil {
		h.servers[serverID] = make(map[string]*Client)
	}
	h.servers[serverID][c.id] = c
	if c.servers == nil {
		c.servers = make(map[string]struct{})
	}
	c.servers[serverID] = struct{}{}
	h.refreshPresenceLocked(h.serverClientsLocked(serverID))
}

// UnsubscribeFromServer removes the client from the server's subscriber set.
// Rituals fork: when c was subscribed, serverID then goes to the server
// activity hook, outside the lock.
func (h *Hub) UnsubscribeFromServer(c *Client, serverID string) {
	if h.unsubscribeFromServer(c, serverID) {
		h.noteServerActivity(c, []string{serverID})
	}
}

// unsubscribeFromServer is UnsubscribeFromServer under h.mu (released by
// defer, as in unregister); it reports whether c was subscribed.
func (h *Hub) unsubscribeFromServer(c *Client, serverID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.servers[serverID][c.id]; !ok {
		return false
	}
	affected := h.serverClientsLocked(serverID)
	h.unsubscribeServerLocked(c, serverID)
	h.refreshPresenceLocked(affected)
	return true
}

// unsubscribeServerLocked drops c from serverID's set. Caller holds h.mu.
func (h *Hub) unsubscribeServerLocked(c *Client, serverID string) {
	if m := h.servers[serverID]; m != nil {
		delete(m, c.id)
		if len(m) == 0 {
			delete(h.servers, serverID)
		}
	}
	delete(c.servers, serverID)
}

// DisconnectUserFromServer removes every connection of userID from one
// server and the given channels without closing any socket, so the person's
// other Spaces on the same connection stay live.
//
// Rituals fork (wire contract Item 3, D18): replaces the instance-wide
// DisconnectUser for a Rituals sync removal. A connection that was not
// subscribed to serverID missed the member_kicked broadcast, so it gets the
// same frame directly; a subscribed one already has it and gets nothing
// twice. Presence is recomputed for everyone who shared the server.
// A non-empty reason is added to that direct frame as "reason", as in the
// broadcast one (Rituals: "device_limit" for the device seat cap; a revoke
// passes ""). This server-side removal is not reported as activity.
func (h *Hub) DisconnectUserFromServer(userID, serverID string, channelIDs []string, reason string) {
	if userID == "" || serverID == "" {
		return
	}
	frame := map[string]interface{}{
		"type":      "member_kicked",
		"server_id": serverID,
		"user_id":   userID,
	}
	if reason != "" {
		frame["reason"] = reason
	}
	kicked, _ := json.Marshal(frame)
	h.mu.Lock()
	defer h.mu.Unlock()
	affected := h.serverClientsLocked(serverID)
	for _, c := range h.clients {
		if c.userID != userID {
			continue
		}
		if _, subscribed := h.servers[serverID][c.id]; subscribed {
			h.unsubscribeServerLocked(c, serverID)
		} else {
			select {
			case c.send <- kicked:
			default:
				slog.Warn("ws client send buffer full", "clientID", c.id)
			}
		}
		for _, channelID := range channelIDs {
			if m := h.channels[channelID]; m != nil {
				delete(m, c.id)
				if len(m) == 0 {
					delete(h.channels, channelID)
				}
			}
		}
		affected = append(affected, c)
	}
	h.refreshPresenceLocked(affected)
}

// SetSubscribeHook installs fn, called after an accepted channel subscribe
// with that client's user id; each frame it returns is queued to that client
// only, after the subscription took effect. Rituals uses it to replay
// pending MLS remove requests (wire contract Item 2, D15). nil removes it.
func (h *Hub) SetSubscribeHook(fn func(ctx context.Context, channelID, userID string) [][]byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subscribeHook = fn
}

func (h *Hub) subscribeHookFn() func(ctx context.Context, channelID, userID string) [][]byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.subscribeHook
}

// SetServerActivityHook installs fn, called with a local user's id and the
// server ids involved after that user's connection subscribes to a server,
// unsubscribes from one it was subscribed to, or unregisters while
// subscribed to some. It runs on that connection's goroutine (its read pump,
// or Run's deferred Unregister) after h.mu is released, never under it, so
// fn must return at once: no I/O there (hand it off), and no call back into
// the hub's write paths. Federated connections are not reported. Rituals
// uses it to keep each device seat's last activity
// (rituals.seats.last_active_at). nil removes it.
func (h *Hub) SetServerActivityHook(fn func(userID string, serverIDs []string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.serverActivityHook = fn
}

// noteServerActivity calls the server activity hook for c. Caller must not
// hold h.mu.
func (h *Hub) noteServerActivity(c *Client, serverIDs []string) {
	if len(serverIDs) == 0 || c.userID == "" || c.federatedIdentityID != "" {
		return
	}
	h.mu.RLock()
	fn := h.serverActivityHook
	h.mu.RUnlock()
	if fn == nil {
		return
	}
	fn(c.userID, serverIDs)
}

// BroadcastToServer sends the message to all clients subscribed to the given server.
func (h *Hub) BroadcastToServer(serverID string, message []byte) {
	h.mu.RLock()
	m := h.servers[serverID]
	if m == nil {
		h.mu.RUnlock()
		return
	}
	clients := make([]*Client, 0, len(m))
	for _, c := range m {
		clients = append(clients, c)
	}
	h.mu.RUnlock()
	for _, c := range clients {
		select {
		case c.send <- message:
		default:
			slog.Warn("ws client send buffer full", "clientID", c.id)
		}
	}
}

// BroadcastToAll sends the message to all connected clients.
func (h *Hub) BroadcastToAll(message []byte) {
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for _, c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()
	for _, c := range clients {
		select {
		case c.send <- message:
		default:
			slog.Warn("ws client send buffer full", "clientID", c.id)
		}
	}
}

// BroadcastToUser sends the message to all connected clients for the given userID.
func (h *Hub) BroadcastToUser(userID string, message []byte) {
	h.mu.RLock()
	clients := make([]*Client, 0)
	for _, c := range h.clients {
		if c.userID == userID {
			clients = append(clients, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range clients {
		select {
		case c.send <- message:
		default:
			slog.Warn("ws client send buffer full", "clientID", c.id)
		}
	}
}

// BroadcastToFederatedUser sends the message to all connected clients
// for the given federated identity ID.
func (h *Hub) BroadcastToFederatedUser(federatedIdentityID string, message []byte) {
	h.mu.RLock()
	clients := make([]*Client, 0)
	for _, c := range h.clients {
		if c.federatedIdentityID == federatedIdentityID {
			clients = append(clients, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range clients {
		select {
		case c.send <- message:
		default:
			slog.Warn("ws client send buffer full", "clientID", c.id)
		}
	}
}

// BroadcastToUserInChannel sends the message to all clients for userID that are subscribed to channelID.
func (h *Hub) BroadcastToUserInChannel(channelID, userID string, message []byte) {
	h.mu.RLock()
	m := h.channels[channelID]
	if m == nil {
		h.mu.RUnlock()
		return
	}
	clients := make([]*Client, 0)
	for _, c := range m {
		if c.userID == userID {
			clients = append(clients, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range clients {
		select {
		case c.send <- message:
		default:
			slog.Warn("ws client send buffer full", "clientID", c.id)
		}
	}
}

// Broadcast sends the message to all clients subscribed to the channel (except excludeClientID if non-empty).
func (h *Hub) Broadcast(channelID string, message []byte, excludeClientID string) {
	h.mu.RLock()
	m := h.channels[channelID]
	if m == nil {
		h.mu.RUnlock()
		return
	}
	clients := make([]*Client, 0, len(m))
	for id, c := range m {
		if id != excludeClientID {
			clients = append(clients, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range clients {
		select {
		case c.send <- message:
		default:
			slog.Warn("ws client send buffer full", "clientID", c.id)
		}
	}
}

// DisconnectDevice closes any active WebSocket connection bound to the
// given (userID, deviceID) pair. Called by the device-revoke handler
// so the revoked device's currently-open WS session is dropped right
// after its device key is deleted, instead of waiting for its next
// reconnect to fail authentication.
func (h *Hub) DisconnectDevice(userID, deviceID string) {
	if userID == "" || deviceID == "" {
		return
	}
	h.mu.RLock()
	targets := make([]*Client, 0)
	for _, c := range h.clients {
		if c.userID == userID && c.deviceID == deviceID {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range targets {
		_ = c.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "device revoked"))
		_ = c.conn.Close()
	}
}

// DisconnectUser closes all WebSocket connections for the given user ID.
// Used by kick/ban handlers to force the user offline.
func (h *Hub) DisconnectUser(userID string) {
	h.mu.RLock()
	targets := make([]*Client, 0)
	for _, c := range h.clients {
		if c.userID == userID {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range targets {
		_ = c.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "removed from instance"))
		_ = c.conn.Close()
	}
}

// HubStats is a point-in-time snapshot of Hub population counters used by
// operator-facing metrics endpoints. All fields are non-negative.
type HubStats struct {
	Clients            int `json:"clients"`
	PresentIdentities  int `json:"presentIdentities"`
	SubscribedChannels int `json:"subscribedChannels"`
	SubscribedServers  int `json:"subscribedServers"`
}

// Stats returns the current Hub population. Cheap; takes only the read lock.
func (h *Hub) Stats() HubStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return HubStats{
		Clients:            len(h.clients),
		PresentIdentities:  len(h.presence),
		SubscribedChannels: len(h.channels),
		SubscribedServers:  len(h.servers),
	}
}

// ConnectedUsers reports which of userIDs (local users) have at least one
// connection registered on this hub. Read lock only and no I/O, and no hub
// path does database work under h.mu, so it is safe to call while a database
// transaction is open (Rituals fork: the device seat cap, retireOldSeats).
func (h *Hub) ConnectedUsers(userIDs []string) map[string]bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]bool, len(userIDs))
	for _, id := range userIDs {
		if _, ok := h.presence[id]; ok {
			out[id] = true
		}
	}
	return out
}

// presenceKey is the identity a client contributes to presence.
func presenceKey(c *Client) string {
	if c.federatedIdentityID != "" {
		return "fed:" + c.federatedIdentityID
	}
	return c.userID
}

// serverClientsLocked lists the clients subscribed to serverID.
func (h *Hub) serverClientsLocked(serverID string) []*Client {
	m := h.servers[serverID]
	out := make([]*Client, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	return out
}

// serverPeersLocked lists c and every client sharing a subscribed server
// with c: the clients whose presence list can change when c comes or goes.
func (h *Hub) serverPeersLocked(c *Client) []*Client {
	out := []*Client{c}
	for serverID := range c.servers {
		out = append(out, h.serverClientsLocked(serverID)...)
	}
	return out
}

// presenceListLocked is what client c may see (wire contract Item 4, D21):
// itself plus every identity with a connection subscribed to a server c is
// subscribed to, sorted. Nobody learns who is online outside the Spaces they
// share, so presence never reveals membership to a non-member.
func (h *Hub) presenceListLocked(c *Client) []string {
	seen := map[string]struct{}{presenceKey(c): {}}
	for serverID := range c.servers {
		for _, o := range h.servers[serverID] {
			seen[presenceKey(o)] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// refreshPresenceLocked recomputes the list of each registered client in
// clients and sends {"type":"presence.update","user_ids":[...]} only when it
// differs from the last list that client received. Caller holds h.mu.
func (h *Hub) refreshPresenceLocked(clients []*Client) {
	done := make(map[string]struct{}, len(clients))
	for _, c := range clients {
		if _, dup := done[c.id]; dup {
			continue
		}
		done[c.id] = struct{}{}
		if _, registered := h.clients[c.id]; !registered {
			continue
		}
		msg, _ := json.Marshal(map[string]interface{}{
			"type":     "presence.update",
			"user_ids": h.presenceListLocked(c),
		})
		if string(msg) == c.lastPresence {
			continue
		}
		select {
		case c.send <- msg:
			c.lastPresence = string(msg)
		default:
		}
	}
}
