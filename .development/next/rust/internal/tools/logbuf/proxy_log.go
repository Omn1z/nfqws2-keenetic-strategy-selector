package logbuf

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
)

const proxyLogLimit = 128 * 1024

type proxyLog struct {
	path string
	mu   sync.Mutex
}

func newProxyLog(path string) *proxyLog {
	log := &proxyLog{path: path}
	// Repair an oversized file left by an older installation without creating
	// an empty log when there are no proxy errors yet.
	if f, size, err := log.open(false); err == nil {
		_, _ = retainLogTail(f, size, proxyLogLimit)
		_ = f.Close()
	}
	return log
}

func (l *proxyLog) Write(p []byte) (int, error) {
	if len(p) > proxyLogLimit {
		return 0, io.ErrShortWrite
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, size, err := l.open(true)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if size+int64(len(p)) > proxyLogLimit {
		// Leave room for the next batch of errors and avoid rewriting the tail
		// on every write near the limit. Keep all bytes in this one log file.
		retain := min(int64(proxyLogLimit/2), int64(proxyLogLimit-len(p)))
		size, err = retainLogTail(f, size, retain)
		if err != nil {
			return 0, err
		}
	}
	return f.WriteAt(p, size)
}

func (l *proxyLog) open(create bool) (*os.File, int64, error) {
	info, err := os.Lstat(l.path)
	if os.IsNotExist(err) && create {
		f, err := os.OpenFile(l.path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		return f, 0, err
	}
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("proxy log path is not a regular file")
	}
	f, err := os.OpenFile(l.path, os.O_RDWR, 0)
	if err != nil {
		return nil, 0, err
	}
	opened, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if !os.SameFile(info, opened) {
		f.Close()
		return nil, 0, fmt.Errorf("proxy log file changed while opening")
	}
	if opened.Mode().Perm()&0077 != 0 {
		if err = f.Chmod(0600); err != nil {
			f.Close()
			return nil, 0, err
		}
	}
	return f, opened.Size(), nil
}

func retainLogTail(f *os.File, size, retain int64) (int64, error) {
	if size <= retain {
		return size, nil
	}
	// Read the preceding newline as well, so an exactly aligned first record
	// is kept and a partial one is discarded.
	tail := make([]byte, retain+1)
	if _, err := f.ReadAt(tail, size-int64(len(tail))); err != nil {
		return 0, err
	}
	if newline := bytes.IndexByte(tail, '\n'); newline >= 0 {
		tail = tail[newline+1:]
	} else {
		tail = nil
	}
	if _, err := f.WriteAt(tail, 0); err != nil {
		return 0, err
	}
	size = int64(len(tail))
	return size, f.Truncate(size)
}
