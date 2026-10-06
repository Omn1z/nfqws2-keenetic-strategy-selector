package tgws

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestWSUpgradeFailureAndCancellationCloseTransport(t *testing.T) {
	for _, cancelUpgrade := range []bool{false, true} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		closed := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				closed <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			reader := bufio.NewReader(conn)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					closed <- err
					return
				}
				if line == "\r\n" {
					break
				}
			}
			if cancelUpgrade {
				cancel()
			} else {
				_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			}
			_, err = io.ReadAll(reader)
			closed <- err
		}()
		ws, err := connectWS(ctx, listener.Addr().String(), "test.example", time.Second, wsPath, 0, false)
		cancel()
		_ = listener.Close()
		if ws != nil || err == nil {
			t.Fatalf("failed upgrade returned ws=%v error=%v", ws, err)
		}
		select {
		case err := <-closed:
			if err != nil {
				t.Fatalf("failed upgrade leaked transport: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("upstream transport did not close")
		}
	}
}
