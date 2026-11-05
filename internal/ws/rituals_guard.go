package ws

import "encoding/json"

// clientFrameRequestsRemove reports whether a client-sent mls.add_request
// frame asks for a member removal (action "remove").
//
// Rituals fork: online clients commit the Remove named by such a frame
// without checking who sent it (hush-web useTextChannelMLSCommitListener), so
// only the server may build one (handleMLSLeaveProposal, Rituals sync).
// Keys are compared exactly, as JSON.parse does on the client (Go's struct
// decoding would match "Action" too); an unparseable frame counts as a remove
// so it is never relayed.
func clientFrameRequestsRemove(raw []byte) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return true
	}
	value, ok := fields["action"]
	if !ok {
		return false
	}
	var action string
	if err := json.Unmarshal(value, &action); err != nil {
		return false // not a string: the client ignores it (action !== "remove")
	}
	return action == "remove"
}
