package tgws

import (
	"bytes"
	"time"
)

const (
	cfH2ReplayHistoryBytes   = 64 << 10
	cfH2ReplayHistoryPackets = 16
	cfH2ReplayMaxAttempts    = 3
	cfH2ReplaySlots          = 2
	cfH2ReplayRequestAge     = 3 * time.Second
	cfH2ReplayMaxAge         = 30 * time.Second
	cfH2ReplayRetry          = 2 * time.Second
	cfH2ReplaySlotAge        = 30 * time.Second
)

type cfH2Replay struct {
	body                []byte
	sentAt, lastAttempt time.Time
	attempts            int
	originals           map[*cfH2Request]struct{}
	pending             *cfH2Request
	retired             bool
}

func (c *cfH2Channel) rememberLocked(body []byte, now time.Time) *cfH2Replay {
	var key [8]byte
	copy(key[:], body)
	if key == [8]byte{} {
		return nil
	} // Never replay plaintext auth-key handshakes.
	if c.replayKey != key {
		c.history = nil
		c.replayKey = key
	}
	if len(body) > cfH2ReplayHistoryBytes {
		return nil
	}
	for _, entry := range c.history {
		if bytes.Equal(entry.body, body) {
			return entry
		}
	}
	entry := &cfH2Replay{body: body, sentAt: now, originals: make(map[*cfH2Request]struct{})}
	c.history = append(c.history, entry)
	size := 0
	for _, p := range c.history {
		size += len(p.body)
	}
	for len(c.history) > cfH2ReplayHistoryPackets || size > cfH2ReplayHistoryBytes {
		victim := 0
		for i, p := range c.history {
			if len(p.originals) == 0 && !(p.retired && p.attempts < cfH2ReplayMaxAttempts && now.Sub(p.sentAt) <= cfH2ReplayMaxAge) {
				victim = i
				break
			}
		}
		size -= len(c.history[victim].body)
		copy(c.history[victim:], c.history[victim+1:])
		c.history[len(c.history)-1] = nil
		c.history = c.history[:len(c.history)-1]
	}
	return entry
}

func (c *cfH2Channel) overdueLocked(entry *cfH2Replay, now time.Time) bool {
	if entry.retired {
		return true
	}
	for r := range entry.originals {
		if !r.sent.IsZero() && !r.receiving && now.Sub(r.sent) >= cfH2ReplayRequestAge {
			return true
		}
	}
	return false
}

func (c *cfH2Channel) replayDueLocked(entry *cfH2Replay, now time.Time) bool {
	if now.Before(entry.sentAt) || now.Sub(entry.sentAt) > cfH2ReplayMaxAge || entry.attempts >= cfH2ReplayMaxAttempts {
		return false
	}
	latest := len(c.history) > 0 && c.history[len(c.history)-1] == entry
	if len(entry.originals) == 0 && !entry.retired && !latest {
		return false
	}
	if c.replyBytes > 0 || c.delivering {
		return false
	}
	for r := range entry.originals {
		if r.receiving {
			return false
		}
	}
	if entry.pending != nil && entry.pending.receiving {
		return false
	}
	if entry.attempts > 0 && now.Sub(entry.lastAttempt) < cfH2ReplayRetry {
		return false
	}
	if c.overdueLocked(entry, now) {
		return true
	}
	if !latest {
		return false
	}
	for r := range c.pending {
		if r != entry.pending {
			return false
		}
	}
	return entry.attempts == 0 || now.Sub(c.lastProgress) >= time.Second
}

func (c *cfH2Channel) rotateLocked(r *cfH2Request, retire bool) {
	r.rotated = true
	if retire && r.packet != nil {
		r.packet.retired = true
	}
	r.cancel()
}

// Only retire packets we can replay. Dropping arbitrary encrypted uploads to
// make room could silently lose a Telegram request or attachment.
func (c *cfH2Channel) capacityCandidateLocked(now time.Time) *cfH2Request {
	var candidate *cfH2Request
	for r := range c.pending {
		if r.rotated || r.receiving || r.sent.IsZero() || now.Sub(r.sent) < cfH2ReplayRequestAge {
			continue
		}
		if !r.replay && (r.packet == nil || now.Sub(r.packet.sentAt) > cfH2ReplayMaxAge) {
			continue
		}
		if !r.replay {
			retained := false
			for _, entry := range c.history {
				if entry == r.packet {
					retained = true
					break
				}
			}
			if !retained {
				continue
			}
		}
		if candidate == nil || (r.replay && !candidate.replay) || (r.replay == candidate.replay && r.sent.Before(candidate.sent)) {
			candidate = r
		}
	}
	return candidate
}

func (c *cfH2Channel) makeUploadRoomLocked(now time.Time) {
	if !c.waiting {
		return
	}
	if !c.hasCapacityLocked(c.waitSize) {
		if r := c.capacityCandidateLocked(now); r != nil {
			c.rotateLocked(r, !r.replay)
		}
		return
	}
	if c.lane.hasCapacityLocked(c.waitSize) {
		return
	}
	var oldest *cfH2Request
	var owner *cfH2Channel
	for other := range c.lane.channels {
		if r := other.capacityCandidateLocked(now); r != nil && (oldest == nil || r.sent.Before(oldest.sent)) {
			oldest, owner = r, other
		}
	}
	if oldest != nil {
		owner.rotateLocked(oldest, !oldest.replay)
	}
}

func (c *cfH2Channel) recover() {
	defer c.wg.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			c.lane.mu.Lock()
			if c.err == nil && c.ctx.Err() == nil {
				c.recoverLocked(now)
			}
			c.lane.mu.Unlock()
		}
	}
}

func (c *cfH2Channel) replayCandidateLocked(now time.Time) *cfH2Replay {
	// Old overdue originals first, then the newest completed packet for polling.
	var candidate *cfH2Replay
	for _, entry := range c.history {
		if !c.replayDueLocked(entry, now) {
			continue
		}
		// A live replay may continue waiting for a long poll. It must not
		// prevent an unrelated overdue packet from using the second slot.
		if pending := entry.pending; pending != nil && (pending.rotated || pending.receiving || pending.sent.IsZero() || now.Sub(pending.sent) < cfH2ReplaySlotAge) {
			continue
		}
		if candidate == nil || c.overdueLocked(entry, now) && !c.overdueLocked(candidate, now) {
			candidate = entry
		}
	}
	return candidate
}

func (c *cfH2Channel) recoverLocked(now time.Time) {
	c.makeUploadRoomLocked(now)
	if c.waiting || c.replyBytes > 0 || c.delivering {
		return
	}
	candidate := c.replayCandidateLocked(now)
	if candidate == nil {
		return
	}
	if pending := candidate.pending; pending != nil {
		if !pending.rotated && !pending.receiving && !pending.sent.IsZero() && now.Sub(pending.sent) >= cfH2ReplaySlotAge {
			c.rotateLocked(pending, false)
		}
		return // Capacity is returned by the canceled request, never optimistically.
	}
	replays := 0
	var oldest *cfH2Request
	for r := range c.pending {
		if !r.replay {
			continue
		}
		replays++
		if !r.rotated && !r.receiving && !r.sent.IsZero() && now.Sub(r.sent) >= cfH2ReplaySlotAge && (oldest == nil || r.sent.Before(oldest.sent)) {
			oldest = r
		}
	}
	if replays >= cfH2ReplaySlots {
		if oldest != nil {
			c.rotateLocked(oldest, false)
		}
		return
	}
	if !c.hasCapacityLocked(len(candidate.body)) || !c.lane.hasCapacityLocked(len(candidate.body)) {
		return
	}
	c.startLocked(candidate.body, candidate, true)
}
