package ws

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestClient creates a Client suitable for hub-only tests (no real WebSocket).
func newTestClient(hub *Hub, userID string) *Client {
	return NewClient(nil, hub, userID, userID+"-device", "", nil)
}

// drainPresence reads from the client's send channel and returns the user_ids
// from the first presence.update message found within the timeout.
func drainPresence(t *testing.T, c *Client, timeout time.Duration) []string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case raw := <-c.send:
			var msg struct {
				Type    string   `json:"type"`
				UserIDs []string `json:"user_ids"`
			}
			require.NoError(t, json.Unmarshal(raw, &msg))
			if msg.Type == "presence.update" {
				sort.Strings(msg.UserIDs)
				return msg.UserIDs
			}
		case <-deadline:
			t.Fatal("timed out waiting for presence.update")
			return nil
		}
	}
}

// drainAllMessages reads all pending messages from the send channel within the timeout.
func drainAllMessages(c *Client, timeout time.Duration) [][]byte {
	var msgs [][]byte
	deadline := time.After(timeout)
	for {
		select {
		case raw := <-c.send:
			msgs = append(msgs, raw)
		case <-deadline:
			return msgs
		}
	}
}

func TestHub_RegisterClient_AddsToPresence(t *testing.T) {
	hub := NewHub()
	c := newTestClient(hub, "user-1")

	hub.Register(c)

	ids := drainPresence(t, c, 100*time.Millisecond)
	assert.Equal(t, []string{"user-1"}, ids)
}

func TestHub_UnregisterClient_RemovesFromPresence(t *testing.T) {
	hub := NewHub()
	c := newTestClient(hub, "user-1")
	observer := newTestClient(hub, "observer")

	hub.Register(observer)
	hub.SubscribeToServer(observer, "server-1")
	_ = drainAllMessages(observer, 50*time.Millisecond)

	hub.Register(c)
	hub.SubscribeToServer(c, "server-1")
	_ = drainAllMessages(c, 50*time.Millisecond)
	_ = drainAllMessages(observer, 50*time.Millisecond)

	hub.Unregister(c)

	ids := drainPresence(t, observer, 100*time.Millisecond)
	assert.Equal(t, []string{"observer"}, ids)
}

func TestHub_MultipleSessionsSameUser_PresenceStaysOnPartialDisconnect(t *testing.T) {
	hub := NewHub()
	c1 := newTestClient(hub, "user-1")
	c2 := newTestClient(hub, "user-1")
	observer := newTestClient(hub, "observer")

	for _, c := range []*Client{observer, c1, c2} {
		hub.Register(c)
		hub.SubscribeToServer(c, "server-1")
	}
	_ = drainAllMessages(c1, 50*time.Millisecond)
	_ = drainAllMessages(c2, 50*time.Millisecond)
	_ = drainAllMessages(observer, 50*time.Millisecond)

	hub.Unregister(c1)

	// user-1 is still online through c2: nobody's list changed, so nothing is sent.
	assert.Empty(t, drainAllMessages(observer, 50*time.Millisecond))
	assert.Empty(t, drainAllMessages(c2, 50*time.Millisecond))
	hub.mu.RLock()
	ids := hub.presenceListLocked(observer)
	hub.mu.RUnlock()
	assert.Equal(t, []string{"observer", "user-1"}, ids)
}

func TestHub_MultipleSessionsSameUser_PresenceRemovedOnFullDisconnect(t *testing.T) {
	hub := NewHub()
	observer := newTestClient(hub, "observer")
	hub.Register(observer)
	hub.SubscribeToServer(observer, "server-1")
	_ = drainAllMessages(observer, 50*time.Millisecond)

	c1 := newTestClient(hub, "user-1")
	c2 := newTestClient(hub, "user-1")
	hub.Register(c1)
	hub.Register(c2)
	hub.SubscribeToServer(c1, "server-1")
	hub.SubscribeToServer(c2, "server-1")
	_ = drainAllMessages(observer, 50*time.Millisecond)

	hub.Unregister(c1)
	_ = drainAllMessages(observer, 50*time.Millisecond)

	hub.Unregister(c2)

	ids := drainPresence(t, observer, 100*time.Millisecond)
	assert.Equal(t, []string{"observer"}, ids)
}

// presenceFrames returns the user_ids of every presence.update queued for c.
func presenceFrames(t *testing.T, c *Client) [][]string {
	t.Helper()
	var out [][]string
	for _, raw := range drainAllMessages(c, 50*time.Millisecond) {
		var msg struct {
			Type    string   `json:"type"`
			UserIDs []string `json:"user_ids"`
		}
		require.NoError(t, json.Unmarshal(raw, &msg))
		if msg.Type == "presence.update" {
			out = append(out, msg.UserIDs)
		}
	}
	return out
}

func TestHub_Presence_ScopedToSharedServers(t *testing.T) {
	hub := NewHub()
	alice := newTestClient(hub, "alice")
	bob := newTestClient(hub, "bob")
	stranger := newTestClient(hub, "stranger")
	for _, c := range []*Client{alice, bob, stranger} {
		hub.Register(c)
	}
	// Registered but sharing nothing: each sees only itself.
	assert.Equal(t, [][]string{{"alice"}}, presenceFrames(t, alice))
	assert.Equal(t, [][]string{{"bob"}}, presenceFrames(t, bob))
	assert.Equal(t, [][]string{{"stranger"}}, presenceFrames(t, stranger))

	hub.SubscribeToServer(alice, "space-1")
	assert.Empty(t, presenceFrames(t, alice), "unchanged list is not re-sent")
	hub.SubscribeToServer(bob, "space-1")
	hub.SubscribeToServer(stranger, "space-2")
	assert.Equal(t, [][]string{{"alice", "bob"}}, presenceFrames(t, alice))
	assert.Equal(t, [][]string{{"alice", "bob"}}, presenceFrames(t, bob))
	assert.Empty(t, presenceFrames(t, stranger), "a non-member never learns who is in space-1")

	// Bob's other connection subscribing changes nobody's list.
	bob2 := newTestClient(hub, "bob")
	hub.Register(bob2)
	hub.SubscribeToServer(bob2, "space-1")
	assert.Equal(t, [][]string{{"bob"}, {"alice", "bob"}}, presenceFrames(t, bob2))
	assert.Empty(t, presenceFrames(t, alice))

	// Leaving the server shrinks both sides' lists.
	hub.UnsubscribeFromServer(bob, "space-1")
	hub.UnsubscribeFromServer(bob2, "space-1")
	assert.Equal(t, [][]string{{"bob"}}, presenceFrames(t, bob))
	assert.Equal(t, [][]string{{"alice"}}, presenceFrames(t, alice))
	assert.Empty(t, presenceFrames(t, stranger))

	// Unsubscribing twice is a no-op.
	hub.UnsubscribeFromServer(bob, "space-1")
	assert.Empty(t, presenceFrames(t, bob))
}

func TestHub_DisconnectUserFromServer(t *testing.T) {
	hub := NewHub()
	alice := newTestClient(hub, "alice")
	bobIn := newTestClient(hub, "bob")  // subscribed to space-1
	bobOut := newTestClient(hub, "bob") // a connection that never opened space-1
	for _, c := range []*Client{alice, bobIn, bobOut} {
		hub.Register(c)
	}
	hub.SubscribeToServer(alice, "space-1")
	hub.SubscribeToServer(bobIn, "space-1")
	hub.SubscribeToServer(bobIn, "space-2")
	hub.Subscribe(alice, "text-1")
	hub.Subscribe(bobIn, "text-1")
	hub.Subscribe(bobOut, "text-1")
	hub.Subscribe(bobIn, "text-2")
	for _, c := range []*Client{alice, bobIn, bobOut} {
		_ = drainAllMessages(c, 50*time.Millisecond)
	}

	hub.DisconnectUserFromServer("bob", "space-1", []string{"text-1", "voice-1"})

	// The subscribed connection already got member_kicked from the server
	// broadcast; only the other one gets it directly.
	var kicked []map[string]interface{}
	for _, raw := range drainAllMessages(bobOut, 50*time.Millisecond) {
		var m map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &m))
		if m["type"] == "member_kicked" {
			kicked = append(kicked, m)
		}
	}
	require.Len(t, kicked, 1)
	assert.Equal(t, "space-1", kicked[0]["server_id"])
	assert.Equal(t, "bob", kicked[0]["user_id"])
	for _, raw := range drainAllMessages(bobIn, 50*time.Millisecond) {
		assert.NotContains(t, string(raw), "member_kicked")
	}

	hub.mu.RLock()
	_, stillServer := hub.servers["space-1"][bobIn.id]
	_, otherServer := hub.servers["space-2"][bobIn.id]
	_, inText1 := hub.channels["text-1"][bobIn.id]
	_, outText1 := hub.channels["text-1"][bobOut.id]
	_, inText2 := hub.channels["text-2"][bobIn.id]
	_, registered := hub.clients[bobIn.id]
	aliceList := hub.presenceListLocked(alice)
	hub.mu.RUnlock()
	assert.False(t, stillServer)
	assert.True(t, otherServer, "other Spaces on the same socket stay live")
	assert.False(t, inText1)
	assert.False(t, outText1)
	assert.True(t, inText2)
	assert.True(t, registered, "no socket is closed")
	assert.Equal(t, []string{"alice"}, aliceList)

	// Broadcasts to the removed channel no longer reach bob.
	hub.Broadcast("text-1", []byte(`{"type":"synthetic"}`), "")
	assert.Empty(t, drainAllMessages(bobIn, 50*time.Millisecond))
	assert.Empty(t, drainAllMessages(bobOut, 50*time.Millisecond))
	assert.Len(t, drainAllMessages(alice, 50*time.Millisecond), 2) // presence change + broadcast
}

func TestHub_SubscribeHookReplaysToSubscriberOnly(t *testing.T) {
	hub := NewHub()
	alice := newTestClient(hub, "alice")
	bob := newTestClient(hub, "bob")
	hub.Register(alice)
	hub.Register(bob)
	_ = drainAllMessages(alice, 50*time.Millisecond)
	_ = drainAllMessages(bob, 50*time.Millisecond)

	alice.replayOnSubscribe("text-1") // no hook: nothing
	assert.Empty(t, drainAllMessages(alice, 50*time.Millisecond))

	var calls []string
	hub.SetSubscribeHook(func(_ context.Context, channelID, userID string) [][]byte {
		calls = append(calls, channelID+"/"+userID)
		return [][]byte{[]byte(`{"n":1}`), []byte(`{"n":2}`)}
	})
	alice.replayOnSubscribe("text-1")
	assert.Equal(t, []string{"text-1/alice"}, calls)
	got := drainAllMessages(alice, 50*time.Millisecond)
	require.Len(t, got, 2)
	assert.Equal(t, `{"n":1}`, string(got[0]))
	assert.Equal(t, `{"n":2}`, string(got[1]))
	assert.Empty(t, drainAllMessages(bob, 50*time.Millisecond))

	hub.SetSubscribeHook(nil)
	alice.replayOnSubscribe("text-1")
	assert.Len(t, calls, 1)
}

func TestHub_Subscribe_ClientReceivesBroadcast(t *testing.T) {
	hub := NewHub()
	c := newTestClient(hub, "user-1")
	hub.Register(c)
	_ = drainAllMessages(c, 50*time.Millisecond)

	hub.Subscribe(c, "channel-1")
	hub.Broadcast("channel-1", []byte(`{"msg":"hello"}`), "")

	select {
	case raw := <-c.send:
		assert.JSONEq(t, `{"msg":"hello"}`, string(raw))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("client did not receive broadcast")
	}
}

func TestHub_Broadcast_ExcludesSender(t *testing.T) {
	hub := NewHub()
	sender := newTestClient(hub, "user-1")
	receiver := newTestClient(hub, "user-2")
	hub.Register(sender)
	hub.Register(receiver)
	_ = drainAllMessages(sender, 50*time.Millisecond)
	_ = drainAllMessages(receiver, 50*time.Millisecond)

	hub.Subscribe(sender, "channel-1")
	hub.Subscribe(receiver, "channel-1")
	hub.Broadcast("channel-1", []byte(`{"msg":"test"}`), sender.id)

	// Receiver should get the message.
	select {
	case raw := <-receiver.send:
		assert.JSONEq(t, `{"msg":"test"}`, string(raw))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("receiver did not get broadcast")
	}

	// Sender should NOT get the message.
	select {
	case raw := <-sender.send:
		t.Fatalf("sender should not receive broadcast, got: %s", raw)
	case <-time.After(50 * time.Millisecond):
		// Expected: nothing received.
	}
}

func TestHub_Unsubscribe_ClientStopsReceiving(t *testing.T) {
	hub := NewHub()
	c := newTestClient(hub, "user-1")
	hub.Register(c)
	_ = drainAllMessages(c, 50*time.Millisecond)

	hub.Subscribe(c, "channel-1")
	hub.Unsubscribe(c, "channel-1")
	hub.Broadcast("channel-1", []byte(`{"msg":"nope"}`), "")

	select {
	case raw := <-c.send:
		t.Fatalf("client should not receive after unsubscribe, got: %s", raw)
	case <-time.After(50 * time.Millisecond):
		// Expected: nothing received.
	}
}

func TestHub_SubscribeMultipleChannels_IsolatedBroadcast(t *testing.T) {
	hub := NewHub()
	c1 := newTestClient(hub, "user-1")
	c2 := newTestClient(hub, "user-2")
	hub.Register(c1)
	hub.Register(c2)
	_ = drainAllMessages(c1, 50*time.Millisecond)
	_ = drainAllMessages(c2, 50*time.Millisecond)

	hub.Subscribe(c1, "channel-A")
	hub.Subscribe(c2, "channel-B")
	hub.Broadcast("channel-A", []byte(`{"ch":"A"}`), "")

	// c1 subscribed to channel-A should receive.
	select {
	case raw := <-c1.send:
		assert.JSONEq(t, `{"ch":"A"}`, string(raw))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("c1 did not receive broadcast on channel-A")
	}

	// c2 subscribed to channel-B should NOT receive.
	select {
	case raw := <-c2.send:
		t.Fatalf("c2 should not receive channel-A broadcast, got: %s", raw)
	case <-time.After(50 * time.Millisecond):
		// Expected: nothing received.
	}
}

func TestHub_UnregisterClient_RemovedFromChannels(t *testing.T) {
	hub := NewHub()
	c := newTestClient(hub, "user-1")
	hub.Register(c)
	_ = drainAllMessages(c, 50*time.Millisecond)

	hub.Subscribe(c, "channel-1")
	hub.Unregister(c)

	// Broadcast to channel-1 should not panic and no one should receive.
	hub.Broadcast("channel-1", []byte(`{"msg":"ghost"}`), "")

	hub.mu.RLock()
	subs := hub.channels["channel-1"]
	hub.mu.RUnlock()
	assert.Empty(t, subs, "channel should have no subscribers after client unregistered")
}
