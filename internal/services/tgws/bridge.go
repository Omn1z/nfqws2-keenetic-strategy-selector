package tgws

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// messageSplitter slices an MTProto byte stream into individual transport
// packets so each becomes its own WS binary frame. It decrypts the
// re-encrypted bytes (in lockstep with upstreamEncrypt) just enough to read
// packet boundaries; the ciphertext itself is what gets framed.
type messageSplitter struct {
	decryptor cipher.Stream
	proto     uint32
	cipherBuf []byte
	plainBuf  []byte
	off       bool // set once we hit an unknown packet shape; stop splitting
}

func newMessageSplitter(relayHandshake []byte, proto uint32) *messageSplitter {
	return &messageSplitter{
		decryptor: upstreamPacketDecryptor(relayHandshake),
		proto:     proto,
	}
}

func (m *messageSplitter) split(chunk []byte) [][]byte {
	if len(chunk) == 0 {
		return nil
	}
	if m.off {
		return [][]byte{chunk}
	}
	m.cipherBuf = append(m.cipherBuf, chunk...)
	plain := make([]byte, len(chunk))
	m.decryptor.XORKeyStream(plain, chunk)
	m.plainBuf = append(m.plainBuf, plain...)

	var parts [][]byte
	for len(m.cipherBuf) > 0 {
		length, ready := m.nextPacketLen()
		if !ready {
			break
		}
		if length <= 0 {
			parts = append(parts, append([]byte(nil), m.cipherBuf...))
			m.cipherBuf = nil
			m.plainBuf = nil
			m.off = true
			break
		}
		parts = append(parts, append([]byte(nil), m.cipherBuf[:length]...))
		m.cipherBuf = m.cipherBuf[length:]
		m.plainBuf = m.plainBuf[length:]
	}
	return parts
}

func (m *messageSplitter) flush() []byte {
	if len(m.cipherBuf) == 0 {
		return nil
	}
	tail := append([]byte(nil), m.cipherBuf...)
	m.cipherBuf = nil
	m.plainBuf = nil
	return tail
}

// nextPacketLen reports the total length of the leading packet. ready=false
// means "need more bytes"; ready=true with length<=0 means an unknown shape.
func (m *messageSplitter) nextPacketLen() (length int, ready bool) {
	if len(m.plainBuf) == 0 {
		return 0, false
	}
	switch m.proto {
	case protoIntAbridged:
		return m.abridgedLen()
	case protoIntIntermediate, protoIntPaddedIntermediate:
		return m.intermediateLen()
	}
	return 0, true
}

func (m *messageSplitter) abridgedLen() (int, bool) {
	first := m.plainBuf[0]
	var payloadLen, headerLen int
	if first == 0x7F || first == 0xFF {
		if len(m.plainBuf) < 4 {
			return 0, false
		}
		payloadLen = (int(m.plainBuf[1]) | int(m.plainBuf[2])<<8 | int(m.plainBuf[3])<<16) * 4
		headerLen = 4
	} else {
		payloadLen = int(first&0x7F) * 4
		headerLen = 1
	}
	if payloadLen <= 0 {
		return 0, true
	}
	total := headerLen + payloadLen
	if len(m.plainBuf) >= total {
		return total, true
	}
	return 0, false
}

func (m *messageSplitter) intermediateLen() (int, bool) {
	if len(m.plainBuf) < 4 {
		return 0, false
	}
	payloadLen := int(binary.LittleEndian.Uint32(m.plainBuf[0:4]) & 0x7FFFFFFF)
	if payloadLen <= 0 {
		return 0, true
	}
	total := 4 + payloadLen
	if len(m.plainBuf) >= total {
		return total, true
	}
	return 0, false
}

// bridgeWS relays a client TCP stream and an upstream WS connection, decrypting
// with one key and re-encrypting with the other in each direction.
func bridgeWS(client io.Reader, clientWriter io.Writer, closeClient func(), ws *rawWebSocket, ctx *reencryptionContext, stats *Stats, splitter *messageSplitter) {
	var once sync.Once
	stop := func() { once.Do(func() { _ = ws.close(); closeClient() }) }

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				stats.bytesUp.Add(int64(n))
				reenc := make([]byte, n)
				ctx.clientDecrypt.XORKeyStream(reenc, buf[:n])
				ctx.upstreamEncrypt.XORKeyStream(reenc, reenc)
				if splitter != nil {
					parts := splitter.split(reenc)
					if len(parts) == 1 {
						if e := ws.send(parts[0]); e != nil {
							return
						}
					} else if len(parts) > 1 {
						if e := ws.sendBatch(parts); e != nil {
							return
						}
					}
				} else if e := ws.send(reenc); e != nil {
					return
				}
			}
			if err != nil {
				if splitter != nil {
					if tail := splitter.flush(); tail != nil {
						_ = ws.send(tail)
					}
				}
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			data, err := ws.recv()
			if err != nil {
				return
			}
			stats.bytesDown.Add(int64(len(data)))
			out := make([]byte, len(data))
			ctx.upstreamDecrypt.XORKeyStream(out, data)
			ctx.clientEncrypt.XORKeyStream(out, out)
			if _, e := clientWriter.Write(out); e != nil {
				return
			}
		}
	}()

	<-done
	stop()
	<-done
}

// bridgeTCP relays a client stream and an upstream TCP connection (the direct
// fallback path) with the same re-encryption.
func bridgeTCP(client io.Reader, clientWriter io.Writer, remote net.Conn, closeClient func(), ctx *reencryptionContext, stats *Stats) {
	var once sync.Once
	stop := func() { once.Do(func() { _ = remote.Close(); closeClient() }) }

	done := make(chan struct{}, 2)
	go func() { // client -> telegram
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				stats.bytesUp.Add(int64(n))
				reenc := make([]byte, n)
				ctx.clientDecrypt.XORKeyStream(reenc, buf[:n])
				ctx.upstreamEncrypt.XORKeyStream(reenc, reenc)
				if _, e := remote.Write(reenc); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { // telegram -> client
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				stats.bytesDown.Add(int64(n))
				reenc := make([]byte, n)
				ctx.upstreamDecrypt.XORKeyStream(reenc, buf[:n])
				ctx.clientEncrypt.XORKeyStream(reenc, reenc)
				if _, e := clientWriter.Write(reenc); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	stop()
	<-done
}
