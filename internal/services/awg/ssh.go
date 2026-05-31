package awg

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client is a minimal SSH client (one connection, sequential commands). It is
// the production implementation of the runner seam used by the provisioner.
type Client struct {
	cli *ssh.Client
}

// Dial connects with the given credentials, performing host-key TOFU: if
// cred.KnownKey is set the server key must match it; otherwise the learned key
// is returned so the caller can pin it.
func Dial(ctx context.Context, cred Credentials) (c *Client, learnedKey string, err error) {
	auths, err := authMethods(cred)
	if err != nil {
		return nil, "", err
	}
	var learned string
	hk := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		learned = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		want := strings.TrimSpace(cred.KnownKey)
		if want != "" && want != learned {
			return fmt.Errorf("ключ хоста изменился — соединение отклонено")
		}
		return nil
	}
	cfg := &ssh.ClientConfig{
		User:            cred.User,
		Auth:            auths,
		HostKeyCallback: hk,
		Timeout:         15 * time.Second,
	}
	addr := net.JoinHostPort(cred.Host, strconv.Itoa(cred.Port))
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("не удалось подключиться к %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, learned, fmt.Errorf("ошибка SSH-рукопожатия: %w", err)
	}
	return &Client{cli: ssh.NewClient(sshConn, chans, reqs)}, learned, nil
}

func authMethods(cred Credentials) ([]ssh.AuthMethod, error) {
	if cred.AuthKind == "key" {
		if strings.TrimSpace(cred.KeyPEM) == "" {
			return nil, fmt.Errorf("не указан приватный SSH-ключ")
		}
		var signer ssh.Signer
		var err error
		if strings.TrimSpace(cred.KeyPass) != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cred.KeyPEM), []byte(cred.KeyPass))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cred.KeyPEM))
		}
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать SSH-ключ: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	return []ssh.AuthMethod{ssh.Password(cred.Password)}, nil
}

// Run executes cmd and returns its stdout/stderr. The command is bounded by ctx.
func (c *Client) Run(ctx context.Context, cmd string) (string, string, error) {
	sess, err := c.cli.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return out.String(), errb.String(), ctx.Err()
	case err := <-done:
		return out.String(), errb.String(), err
	}
}

// Put writes data to a remote file via stdin (so secrets never appear in argv or
// the process list), creating the parent directory and chmod-ing the result.
func (c *Client) Put(ctx context.Context, p string, mode uint32, data []byte) error {
	sess, err := c.cli.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(data)
	var errb bytes.Buffer
	sess.Stderr = &errb
	cmd := fmt.Sprintf(`p=%s; mkdir -p "$(dirname "$p")" && umask 077 && cat > "$p" && chmod %o "$p"`, shellQuote(p), mode)
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Close()
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("запись %s: %v: %s", p, err, strings.TrimSpace(errb.String()))
		}
		return nil
	}
}

func (c *Client) Close() error {
	if c.cli != nil {
		return c.cli.Close()
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
