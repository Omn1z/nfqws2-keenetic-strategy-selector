package tgws

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"sync"
	"time"
)

type h2Channel interface {
	send(context.Context, []byte, bool) error
	receive(context.Context) ([]byte, error)
	close()
}

// bridgeH2 preserves native MTProto transport errors, notably -404 (unknown
// authorization key), so Telegram can recreate its key instead of retrying
// the same unusable connection after an unexplained EOF.
func bridgeH2(parent context.Context, clientR io.Reader, clientW io.Writer, closeClient func(), channel h2Channel, crypto *reencryptionContext, stats *Stats, proto uint32, label string) {
	ctx, cancel := context.WithCancel(parent)
	var closeOnce sync.Once
	closeNative := func() { closeOnce.Do(closeClient) }
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			closeNative()
			channel.close()
		})
	}
	stopOnCancel := context.AfterFunc(parent, stop)
	defer stopOnCancel()
	defer stop()

	// Only the download worker and the final error delivery use this cipher.
	// Serialize them before closing so a concurrent completed HTTP response
	// cannot corrupt the final error's AES-CTR position.
	var writeMu sync.Mutex
	writeNative := func(body []byte) error {
		framed, err := encodeH2Reply(body, proto)
		if err != nil {
			return err
		}
		crypto.clientEncrypt.XORKeyStream(framed, framed)
		for len(framed) > 0 {
			n, err := clientW.Write(framed)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(framed) {
				return io.ErrShortWrite
			}
			framed = framed[n:]
		}
		stats.bytesDown.Add(int64(len(body)))
		return nil
	}
	type result struct {
		source string
		err    error
	}
	done := make(chan result, 2)
	go func() {
		for {
			body, quick, err := readH2Packet(clientR, crypto.clientDecrypt, proto)
			if err != nil {
				done <- result{"native read", err}
				return
			}
			if err := channel.send(ctx, body, quick); err != nil {
				done <- result{"HTTP upload", err}
				return
			}
		}
	}()
	go func() {
		for {
			body, err := channel.receive(ctx)
			if err != nil {
				done <- result{"HTTP download", err}
				return
			}
			writeMu.Lock()
			err = ctx.Err()
			if err == nil {
				err = writeNative(body)
			}
			writeMu.Unlock()
			if delivered, ok := channel.(interface{ delivered() }); ok {
				delivered.delivered()
			}
			if err != nil {
				done <- result{"native write", err}
				return
			}
		}
	}()

	closed := <-done
	cancel()
	var transportErr *mtprotoTransportError
	if state, ok := channel.(interface{ transportError() *mtprotoTransportError }); ok {
		transportErr = state.transportError()
	}
	if transportErr == nil {
		errors.As(closed.err, &transportErr)
	}
	if transportErr != nil && parent.Err() == nil {
		// No client I/O may hold shutdown open indefinitely. This also releases
		// an already-blocked normal response before attempting error delivery.
		timeout := time.AfterFunc(2*time.Second, closeNative)
		writeMu.Lock()
		if parent.Err() == nil {
			var body [4]byte
			binary.LittleEndian.PutUint32(body[:], uint32(transportErr.code))
			_ = writeNative(body[:])
		}
		writeMu.Unlock()
		timeout.Stop()
	}
	stop()
	<-done
	log.Printf("tgws: [%s] H2 session closed (%s: %s)", censorDomains(label), closed.source, censorDomains(closed.err.Error()))
}
