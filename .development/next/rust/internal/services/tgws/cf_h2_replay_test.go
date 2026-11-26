package tgws

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestCFH2ReplaysOverdueEncryptedRequestWithoutCancelingOriginal(t *testing.T) {
	var requests atomic.Int64
	started := make(chan struct{})
	body := cfH2EncryptedPacket(7)
	lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Error("replay changed encrypted MTProto bytes")
		}
		if requests.Add(1) == 1 {
			close(started)
			<-r.Context().Done()
			return
		}
		w.Write([]byte{7, 0, 0, 0})
	})
	c := cfH2TestChannel(t, lane)
	if err := c.send(context.Background(), body, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request not started")
	}
	lane.mu.Lock()
	for r := range c.pending {
		r.sent = time.Now().Add(-4 * time.Second)
	}
	c.recoverLocked(time.Now())
	lane.mu.Unlock()
	reply, err := cfH2TestReceive(t, c)
	if err != nil || len(reply) != 4 || reply[0] != 7 {
		t.Fatalf("replay failed %v %v", reply, err)
	}
	lane.mu.Lock()
	if len(c.pending) != 1 {
		t.Errorf("original long poll was canceled: %d", len(c.pending))
	}
	if c.replyBytes != 4 || lane.replyBytes != 4 {
		t.Error("native write lost memory reservation")
	}
	c.recoverLocked(time.Now().Add(3 * time.Second))
	lane.mu.Unlock()
	if requests.Load() != 2 || lane.stats.h2Replays.Load() != 1 {
		t.Fatal("replayed while native receiver was blocked")
	}
	c.delivered()
	c.close()
	if lane.stats.bytesUp.Load() != 48 {
		t.Fatal("replay traffic omitted from accounting")
	}
}

func TestCFH2ReplayEligibilityAndHistoryLimits(t *testing.T) {
	now := time.Now()
	c := &cfH2Channel{pending: make(map[*cfH2Request]struct{}), lastProgress: now.Add(-2 * time.Second)}
	if c.rememberLocked(cfH2Packet(1), now) != nil {
		t.Fatal("plaintext auth packet retained for replay")
	}
	for i := range 20 {
		c.rememberLocked(cfH2EncryptedPacket(byte(i)), now)
	}
	if len(c.history) != cfH2ReplayHistoryPackets {
		t.Fatalf("history size %d", len(c.history))
	}
	entry := c.history[len(c.history)-1]
	if !c.replayDueLocked(entry, now) {
		t.Fatal("idle encrypted receiver not polled")
	}
	entry.attempts = cfH2ReplayMaxAttempts
	if c.replayDueLocked(entry, now) {
		t.Fatal("replay budget exceeded")
	}
	entry.attempts = 0
	entry.sentAt = now.Add(-31 * time.Second)
	if c.replayDueLocked(entry, now) {
		t.Fatal("expired packet replayed")
	}
	entry.sentAt = now
	c.delivering = true
	if c.replayDueLocked(entry, now) {
		t.Fatal("replayed during native backpressure")
	}
	c.delivering = false
	request := &cfH2Request{sent: now.Add(-4 * time.Second), receiving: true}
	entry.originals[request] = struct{}{}
	if c.replayDueLocked(entry, now) {
		t.Fatal("replayed while original response body arriving")
	}
	request.receiving = false
	if !c.replayDueLocked(entry, now) {
		t.Fatal("overdue original not recovered")
	}
	entry.attempts = 1
	entry.lastAttempt = now.Add(-time.Second)
	if c.replayDueLocked(entry, now) {
		t.Fatal("ignored replay retry backoff")
	}
	changed := cfH2EncryptedPacket(99)
	changed[0] = 2
	c.rememberLocked(changed, now)
	if len(c.history) != 1 {
		t.Fatal("auth-key change retained old packets")
	}
	large := make([]byte, 32<<10)
	large[0] = 2
	for i := range 4 {
		large[16] = byte(i)
		c.rememberLocked(bytes.Clone(large), now)
	}
	size := 0
	for _, p := range c.history {
		size += len(p.body)
	}
	if size > cfH2ReplayHistoryBytes {
		t.Fatal("history byte budget exceeded")
	}
}

func TestCFH2CapacityRotationPreservesReplayablePackets(t *testing.T) {
	var arrived atomic.Int64
	ready := make(chan struct{})
	lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		body, _ := io.ReadAll(r.Body)
		if body[16] == 99 {
			w.Write([]byte{99, 0, 0, 0})
			return
		}
		if arrived.Add(1) == cfH2ChannelRequests {
			close(ready)
		}
		<-r.Context().Done()
	})
	c := cfH2TestChannel(t, lane)
	for i := range cfH2ChannelRequests {
		if err := c.send(context.Background(), cfH2EncryptedPacket(byte(i)), false); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("streams not started")
	}
	result := make(chan error, 1)
	go func() { result <- c.send(context.Background(), cfH2EncryptedPacket(99), false) }()
	deadline := time.Now().Add(time.Second)
	for {
		lane.mu.Lock()
		waiting := c.waiting
		if waiting {
			for r := range c.pending {
				r.sent = time.Now().Add(-4 * time.Second)
			}
			c.makeUploadRoomLocked(time.Now())
		}
		lane.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("send did not wait for capacity")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("rotation did not free stream slot")
	}
	_, err := cfH2TestReceive(t, c)
	if err != nil {
		t.Fatal(err)
	}
	c.delivered()
	lane.mu.Lock()
	retired := false
	for _, p := range c.history {
		retired = retired || p.retired
	}
	lane.mu.Unlock()
	if !retired {
		t.Fatal("retired original was not retained for recovery")
	}
	c.close()
}

func TestCFH2CapacityNeverDropsUnretainedOriginal(t *testing.T) {
	now := time.Now()
	c := &cfH2Channel{pending: make(map[*cfH2Request]struct{})}
	packet := &cfH2Replay{sentAt: now.Add(-time.Second)}
	original := &cfH2Request{sent: now.Add(-4 * time.Second), packet: packet}
	c.pending[original] = struct{}{}
	if c.capacityCandidateLocked(now) != nil {
		t.Fatal("selected packet evicted from replay history")
	}
	c.history = []*cfH2Replay{packet}
	if c.capacityCandidateLocked(now) != original {
		t.Fatal("retained packet unavailable for capacity recovery")
	}
}

func TestCFH2PendingReplayDoesNotStarveAnotherOverduePacket(t *testing.T) {
	now := time.Now()
	pending := &cfH2Request{sent: now.Add(-10 * time.Second), replay: true}
	first := &cfH2Replay{sentAt: now.Add(-20 * time.Second), lastAttempt: now.Add(-10 * time.Second), attempts: 1, retired: true, pending: pending}
	second := &cfH2Replay{sentAt: now.Add(-10 * time.Second), retired: true}
	c := &cfH2Channel{history: []*cfH2Replay{first, second}, pending: map[*cfH2Request]struct{}{pending: {}}}
	if candidate := c.replayCandidateLocked(now); candidate != second {
		t.Fatal("live first replay starved second overdue packet")
	}
	pending.receiving = true
	if candidate := c.replayCandidateLocked(now); candidate != second {
		t.Fatal("receiving first replay starved second overdue packet")
	}
}

func TestCFH2NewReplyIdentityRefreshesReplayBudgetWithoutNativeUpload(t *testing.T) {
	const freshReplies = 6
	var requests atomic.Int64
	lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		count := requests.Add(1)
		if count <= freshReplies {
			w.Write(bytes.Repeat([]byte{byte(count)}, 40))
		}
	})
	c := cfH2TestChannel(t, lane)
	if err := c.send(context.Background(), cfH2EncryptedPacket(1), false); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= freshReplies; index++ {
		reply, err := cfH2TestReceive(t, c)
		if err != nil || !bytes.Equal(reply, bytes.Repeat([]byte{byte(index)}, 40)) {
			t.Fatalf("reply %d: %x %v", index, reply, err)
		}
		c.delivered()
		lane.mu.Lock()
		entry := c.history[0]
		if entry.attempts != 0 {
			t.Errorf("fresh response did not refresh budget: %d", entry.attempts)
		}
		if index > 1 && c.replayDueLocked(entry, time.Now()) {
			t.Error("fresh response erased replay retry/progress backoff")
		}
		lane.mu.Unlock()
		if index < freshReplies {
			cfH2RecoverTestPoll(t, c)
		}
	}
	for range cfH2ReplayMaxAttempts {
		cfH2RecoverTestPoll(t, c)
		cfH2WaitForNoRequests(t, c)
	}
	lane.mu.Lock()
	entry := c.history[0]
	entry.lastAttempt = time.Now().Add(-3 * time.Second)
	c.lastProgress = time.Now().Add(-2 * time.Second)
	c.recoverLocked(time.Now())
	remaining := len(c.pending)
	attempts := entry.attempts
	lane.mu.Unlock()
	if remaining != 0 || attempts != cfH2ReplayMaxAttempts || requests.Load() != freshReplies+cfH2ReplayMaxAttempts {
		t.Fatalf("empty responses extended retry budget: requests=%d pending=%d attempts=%d", requests.Load(), remaining, attempts)
	}
}

func TestCFH2DuplicateReplyIdentityDoesNotRefreshReplayBudget(t *testing.T) {
	var requests atomic.Int64
	lane, _ := cfH2Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return
		}
		count := requests.Add(1)
		// A different tail is not a new MTProto reply identifier. Only the
		// first24 bytes refresh the bounded receiver polling budget upstream.
		reply := bytes.Repeat([]byte{0x5a}, 40)
		reply[len(reply)-1] = byte(count)
		w.Write(reply)
	})
	c := cfH2TestChannel(t, lane)
	if err := c.send(context.Background(), cfH2EncryptedPacket(1), false); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= cfH2ReplayMaxAttempts; index++ {
		if index > 0 {
			cfH2RecoverTestPoll(t, c)
		}
		reply, err := cfH2TestReceive(t, c)
		if err != nil || len(reply) != 40 {
			t.Fatalf("reply %d: %x %v", index, reply, err)
		}
		c.delivered()
	}
	lane.mu.Lock()
	entry := c.history[0]
	entry.lastAttempt = time.Now().Add(-3 * time.Second)
	c.lastProgress = time.Now().Add(-2 * time.Second)
	c.recoverLocked(time.Now())
	remaining := len(c.pending)
	lane.mu.Unlock()
	if remaining != 0 || requests.Load() != 1+cfH2ReplayMaxAttempts {
		t.Fatalf("duplicate identifier refreshed retry budget: requests=%d pending=%d", requests.Load(), remaining)
	}
}

func cfH2RecoverTestPoll(t *testing.T, c *cfH2Channel) {
	t.Helper()
	c.lane.mu.Lock()
	entry := c.history[0]
	if !entry.lastAttempt.IsZero() {
		entry.lastAttempt = time.Now().Add(-3 * time.Second)
	}
	c.lastProgress = time.Now().Add(-2 * time.Second)
	c.recoverLocked(time.Now())
	pending := len(c.pending)
	c.lane.mu.Unlock()
	if pending == 0 {
		t.Fatal("eligible receiver poll was not started")
	}
}

func cfH2WaitForNoRequests(t *testing.T, c *cfH2Channel) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c.lane.mu.Lock()
		pending := len(c.pending)
		c.lane.mu.Unlock()
		if pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP request did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}
