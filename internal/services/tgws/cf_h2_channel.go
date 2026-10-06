package tgws

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
)

type cfH2Request struct {
	body                       []byte
	cancel                     context.CancelFunc
	sent                       time.Time
	receiving, replay, rotated bool
	packet                     *cfH2Replay
}

type cfH2Channel struct {
	lane                     *cfH2Lane
	ctx                      context.Context
	cancel                   context.CancelFunc
	label                    string
	wg                       sync.WaitGroup
	sendGate                 chan struct{}
	err                      error
	pending                  map[*cfH2Request]struct{}
	pendingBytes, replyBytes int
	replies                  [][]byte
	delivering               bool
	deliveringBytes          int
	lastProgress             time.Time
	history                  []*cfH2Replay
	replayKey                [8]byte
	waitSize                 int
	waiting                  bool
}

func (c *cfH2Channel) hasCapacityLocked(size int) bool {
	return len(c.pending) < cfH2ChannelRequests && c.pendingBytes+size <= cfH2ChannelBytes
}

// send returns as soon as a bounded HTTP stream has been scheduled. Waiting for
// its response here would serialize all media behind Telegram's long polls.
func (c *cfH2Channel) send(ctx context.Context, body []byte, quick bool) error {
	if len(body) < 24 || len(body) > cfH2MaxPacket || len(body)%4 != 0 {
		return errors.New("invalid H2 MTProto request length")
	}
	ctx, cancel := context.WithTimeout(ctx, cfH2RequestTimeout)
	defer cancel()
	select {
	case c.sendGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return c.channelError()
	}
	defer func() { <-c.sendGate }()
	l := c.lane
	l.mu.Lock()
	c.waiting, c.waitSize = true, len(body)
	defer func() { c.waiting = false; l.mu.Unlock() }()
	for {
		if c.err != nil {
			return c.err
		}
		if c.ctx.Err() != nil {
			return io.ErrClosedPipe
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c.hasCapacityLocked(len(body)) && l.hasCapacityLocked(len(body)) {
			break
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		case <-c.ctx.Done():
		}
		l.mu.Lock()
	}
	// Own the payload: packet decoders may reuse their input buffers.
	body = bytes.Clone(body)
	entry := c.rememberLocked(body, time.Now())
	c.startLocked(body, entry, false)
	return nil
}

func (c *cfH2Channel) startLocked(body []byte, entry *cfH2Replay, replay bool) {
	ctx, cancel := context.WithTimeout(c.ctx, cfH2RequestTimeout)
	r := &cfH2Request{body: body, cancel: cancel, packet: entry, replay: replay}
	c.pending[r] = struct{}{}
	c.pendingBytes += len(body)
	c.lane.inflight++
	c.lane.queuedBytes += len(body)
	if entry != nil {
		if replay {
			entry.attempts++
			entry.lastAttempt = time.Now()
			entry.pending = r
		} else {
			entry.originals[r] = struct{}{}
		}
	}
	c.lane.stats.h2Requests.Add(1)
	c.lane.stats.bytesUp.Add(int64(len(body)))
	if replay {
		c.lane.stats.h2Replays.Add(1)
	}
	c.wg.Add(1)
	go c.run(ctx, r)
}

func (c *cfH2Channel) run(ctx context.Context, r *cfH2Request) {
	defer c.wg.Done()
	defer r.cancel()
	reply, err := c.post(ctx, r)
	l := c.lane
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(c.pending, r)
	c.pendingBytes -= len(r.body)
	l.inflight--
	l.queuedBytes -= len(r.body)
	if r.packet != nil {
		delete(r.packet.originals, r)
		if r.packet.pending == r {
			r.packet.pending = nil
		}
	}
	if err != nil && c.err == nil && c.ctx.Err() == nil && !r.rotated {
		l.stats.h2Errors.Add(1)
		log.Printf("tgws: [%s] H2 %s request failed: %s", censorDomains(c.label), censorDomains(l.host), censorDomains(err.Error()))
		c.failLocked(err)
	}
	if err == nil && c.err == nil && c.ctx.Err() == nil {
		c.lastProgress = time.Now()
		if len(reply) > 0 {
			// post already reserved reply memory, including all queued responses.
			if len(c.replies) >= 16 {
				c.releaseReplyLocked(len(reply))
				c.failLocked(errors.New("H2 response queue exceeded bound"))
			} else {
				c.replies = append(c.replies, reply)
			}
		}
	} else if len(reply) > 0 {
		c.releaseReplyLocked(len(reply))
	}
	l.signalLocked()
}

var errCFH2ReplyBuffer = errors.New("H2 response buffers exceeded bound")

func (c *cfH2Channel) post(ctx context.Context, r *cfH2Request) (reply []byte, retErr error) {
	l := c.lane
	buffered := 0
	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		r.receiving = false
		if retErr != nil {
			c.releaseReplyLocked(buffered)
			var transportErr *mtprotoTransportError
			if !errors.As(retErr, &transportErr) && !errors.Is(retErr, errCFH2ReplyBuffer) && !r.rotated && c.ctx.Err() == nil && !isWSHandshakeQueueError(retErr) {
				l.failedUntil = time.Now().Add(cfH2Cooldown)
			}
		}
	}()
	trace := &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				l.mu.Lock()
				r.sent = time.Now()
				l.mu.Unlock()
			}
		},
		GotFirstResponseByte: func() { l.mu.Lock(); r.receiving = true; c.lastProgress = time.Now(); l.mu.Unlock() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, l.endpoint, bytes.NewReader(r.body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	// RoundTrip never follows redirects and does not replay POST on a fresh
	// connection: MTProto recovery below has its own explicit bounded budget.
	req.GetBody = nil
	resp, err := l.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		return nil, errors.New("CF /api response requires HTTP/2")
	}
	switch resp.StatusCode {
	case 403, 404, 429, 444:
		return nil, &mtprotoTransportError{code: -int32(resp.StatusCode), source: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	case 200:
	default:
		return nil, fmt.Errorf("CF /api HTTP %d", resp.StatusCode)
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return nil, errors.New("CF /api returned HTML instead of MTProto")
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil, errors.New("CF /api returned unexpected content encoding")
	}
	if resp.ContentLength > cfH2MaxPacket {
		return nil, errors.New("H2 response Content-Length exceeds native packet bound")
	}
	var content bytes.Buffer
	chunk := make([]byte, 32<<10)
	for {
		n, readErr := resp.Body.Read(chunk)
		if n > 0 {
			if content.Len()+n > cfH2MaxPacket {
				return nil, errors.New("H2 response exceeds native packet bound")
			}
			l.mu.Lock()
			if l.replyBytes+n > cfH2LaneBytes || c.replyBytes+n > cfH2ChannelBytes {
				l.mu.Unlock()
				return nil, errCFH2ReplyBuffer
			}
			l.replyBytes += n
			c.replyBytes += n
			buffered += n
			c.lastProgress = time.Now()
			l.mu.Unlock()
			content.Write(chunk[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	if resp.ContentLength >= 0 && int64(content.Len()) != resp.ContentLength {
		return nil, errors.New("incomplete H2 response body")
	}
	if content.Len()%4 != 0 {
		return nil, errors.New("CF /api response is not an aligned MTProto packet")
	}
	if content.Len() == 4 {
		code := int32(binary.LittleEndian.Uint32(content.Bytes()))
		if code < 0 {
			return nil, &mtprotoTransportError{code: code, source: "HTTP 200 payload"}
		}
	}
	return content.Bytes(), nil
}

func (c *cfH2Channel) releaseReplyLocked(size int) { c.replyBytes -= size; c.lane.replyBytes -= size }

func (c *cfH2Channel) receive(ctx context.Context) ([]byte, error) {
	l := c.lane
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if c.err != nil {
			return nil, c.err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if c.ctx.Err() != nil {
			return nil, io.ErrClosedPipe
		}
		if len(c.replies) > 0 {
			body := c.replies[0]
			c.replies[0] = nil
			c.replies = c.replies[1:]
			c.delivering = true
			c.deliveringBytes += len(body)
			return body, nil
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		case <-c.ctx.Done():
		}
		l.mu.Lock()
	}
}

func (c *cfH2Channel) delivered() {
	c.lane.mu.Lock()
	c.releaseReplyLocked(c.deliveringBytes)
	c.deliveringBytes = 0
	c.delivering = false
	c.lastProgress = time.Now()
	c.lane.signalLocked()
	c.lane.mu.Unlock()
}
func (c *cfH2Channel) channelError() error {
	c.lane.mu.Lock()
	defer c.lane.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return io.ErrClosedPipe
}
func (c *cfH2Channel) transportError() *mtprotoTransportError {
	c.lane.mu.Lock()
	defer c.lane.mu.Unlock()
	var err *mtprotoTransportError
	errors.As(c.err, &err)
	return err
}

func (c *cfH2Channel) failLocked(err error) {
	if c.err != nil {
		return
	}
	c.err = err
	c.cancel()
	for _, reply := range c.replies {
		c.releaseReplyLocked(len(reply))
	}
	c.replies = nil
	c.lane.signalLocked()
}

func (c *cfH2Channel) close() {
	c.lane.mu.Lock()
	c.failLocked(io.ErrClosedPipe)
	delete(c.lane.channels, c)
	c.lane.mu.Unlock()
	c.wg.Wait()
	c.lane.mu.Lock()
	c.releaseReplyLocked(c.deliveringBytes)
	c.deliveringBytes = 0
	c.history = nil
	c.lane.mu.Unlock()
}
