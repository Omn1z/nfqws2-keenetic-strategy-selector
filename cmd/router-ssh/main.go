package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"nfqws2strategy/internal/tools/shell"
)

type diagCommand struct {
	name string
	cmd  string
}

var diagCommands = []diagCommand{
	{
		name: "system",
		cmd:  "uname -a; date; uptime",
	},
	{
		name: "accel",
		cmd: "for k in " +
			"net.netfilter.nf_conntrack_fastnat " +
			"net.netfilter.nf_conntrack_fastroute " +
			"net.netfilter.nf_conntrack_fastnat_xfrm " +
			"net.netfilter.nf_conntrack_fastpath_esp " +
			"net.core.swnat net.core.swnat_reset " +
			"net.hwnat.extif_offload net.hwnat.ppe_enabled; do " +
			`printf "%s=" "$k"; sysctl -n "$k" 2>/dev/null || echo NA; done`,
	},
	{
		name: "awg-interfaces",
		cmd: "ip addr show 2>&1 | sed -n '/awg[0-9]/,+7p'; " +
			"grep -E '(awg|nwg|eth3|br0)' /proc/net/dev || true",
	},
	{
		name: "routing",
		cmd: "ip rule show; echo --- table901; ip route show table 901 2>&1; " +
			"echo --- table998; ip route show table 998 2>&1",
	},
	{
		name: "awg-iptables",
		cmd: "for t in mangle nat filter; do echo ===$t===; " +
			"iptables -w -t $t -S 2>/dev/null | grep -Ei 'AWG2|awg[0-9]|TCPMSS|MASQUERADE' || true; done",
	},
	{
		name: "conntrack",
		cmd: `for f in /proc/net/nf_conntrack /proc/net/ip_conntrack; do [ -r "$f" ] && { ` +
			`echo file=$f; echo total=$(wc -l < "$f"); ` +
			`echo fastnat=$(grep -c FASTNAT "$f" 2>/dev/null); ` +
			`echo tunnel_fastnat=$(grep FASTNAT "$f" 2>/dev/null | grep -c 'dst=172.16.0.2'); ` +
			`echo unreplied=$(grep -c UNREPLIED "$f" 2>/dev/null); break; }; done`,
	},
	{
		name: "processes",
		cmd: "ps w 2>/dev/null | grep -Ei 'nfqws|awg|wireguard|strategy|amnezia|nwg' | grep -v grep || true; " +
			"echo --- top; top -b -n 1 2>/dev/null | head -n 18 || true",
	},
}

type globalArgs struct {
	host     string
	port     int
	user     string
	password string
}

func main() {
	if err := runMain(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runMain(args []string) error {
	globals, cmd, rest, err := parseGlobal(args)
	if err != nil {
		return err
	}
	if cmd == "" {
		printUsage(os.Stderr)
		return fmt.Errorf("missing command")
	}
	client, err := dial(globals)
	if err != nil {
		return err
	}
	defer client.Close()

	switch cmd {
	case "exec":
		return runExec(client, rest)
	case "upload":
		return runUpload(client, rest)
	case "download":
		return runDownload(client, rest)
	case "diagnose":
		return runDiagnose(client, rest)
	default:
		printUsage(os.Stderr)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func parseGlobal(args []string) (globalArgs, string, []string, error) {
	fs := flag.NewFlagSet("router-ssh", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g := globalArgs{
		host:     envDefault("ROUTER_HOST", "192.168.3.1"),
		port:     envIntDefault("ROUTER_PORT", 222),
		user:     envDefault("ROUTER_USER", "root"),
		password: envDefault("ROUTER_PASS", "keenetic"),
	}
	fs.StringVar(&g.host, "host", g.host, "router host")
	fs.IntVar(&g.port, "port", g.port, "router SSH port")
	fs.StringVar(&g.user, "user", g.user, "router SSH user")
	fs.StringVar(&g.password, "password", g.password, "router SSH password")
	if err := fs.Parse(args); err != nil {
		printUsage(os.Stderr)
		return g, "", nil, err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return g, "", nil, nil
	}
	return g, rest[0], rest[1:], nil
}

func envDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envIntDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}

func dial(g globalArgs) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            g.user,
		Auth:            []ssh.AuthMethod{ssh.Password(g.password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", net.JoinHostPort(g.host, strconv.Itoa(g.port)), cfg)
}

func runExec(client *ssh.Client, args []string) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	timeout := fs.Duration("timeout", 60*time.Second, "command timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: router-ssh exec [--timeout 60s] <command>")
	}
	rc, err := remoteRun(client, fs.Arg(0), nil, *timeout, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("remote command exited with status %d", rc)
	}
	return nil
}

func runUpload(client *ssh.Client, args []string) error {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mode := fs.String("mode", "0644", "remote chmod mode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: router-ssh upload [--mode 0755] <local> <remote>")
	}
	local := fs.Arg(0)
	remote := fs.Arg(1)
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	remoteDir := posixDir(remote)
	remoteBase := posixBase(remote)
	tmpB64 := remoteDir + "/." + remoteBase + ".upload.b64"
	tmpOut := remoteDir + "/." + remoteBase + ".upload.tmp"
	cmd := strings.Join([]string{
		"mkdir -p " + shell.Quote(remoteDir),
		"cat > " + shell.Quote(tmpB64),
		"base64 -d " + shell.Quote(tmpB64) + " > " + shell.Quote(tmpOut),
		"rm -f " + shell.Quote(tmpB64),
		"chmod " + shell.Quote(*mode) + " " + shell.Quote(tmpOut),
		"mv " + shell.Quote(tmpOut) + " " + shell.Quote(remote),
	}, " && ")
	encoded := base64.StdEncoding.EncodeToString(data)
	rc, err := remoteRun(client, cmd, strings.NewReader(encoded), 3*time.Minute, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("remote upload command exited with status %d", rc)
	}
	fmt.Printf("uploaded %s -> %s (%d bytes)\n", local, remote, len(data))
	return nil
}

func runDownload(client *ssh.Client, args []string) error {
	fs := flag.NewFlagSet("download", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: router-ssh download <remote> <local>")
	}
	remote := fs.Arg(0)
	local := fs.Arg(1)
	var out bytes.Buffer
	rc, err := remoteRun(client, "cat "+shell.Quote(remote), nil, 2*time.Minute, &out, os.Stderr)
	if err != nil {
		return err
	}
	if rc != 0 {
		return fmt.Errorf("remote download command exited with status %d", rc)
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil && filepath.Dir(local) != "." {
		return err
	}
	if err := os.WriteFile(local, out.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("downloaded %s -> %s (%d bytes)\n", remote, local, out.Len())
	return nil
}

func runDiagnose(client *ssh.Client, args []string) error {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	onlyRaw := fs.String("only", "", "comma-separated sections")
	if err := fs.Parse(args); err != nil {
		return err
	}
	only := map[string]bool{}
	for _, item := range strings.Split(*onlyRaw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			only[item] = true
		}
	}
	for _, item := range fs.Args() {
		only[item] = true
	}
	var firstErr error
	for _, d := range diagCommands {
		if len(only) > 0 && !only[d.name] {
			continue
		}
		fmt.Printf("\n===== %s =====\n", d.name)
		rc, err := remoteRun(client, d.cmd, nil, 60*time.Second, os.Stdout, os.Stderr)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if rc != 0 && firstErr == nil {
			firstErr = fmt.Errorf("%s exited with status %d", d.name, rc)
		}
	}
	return firstErr
}

func remoteRun(client *ssh.Client, command string, stdin io.Reader, timeout time.Duration, stdout, stderr io.Writer) (int, error) {
	session, err := client.NewSession()
	if err != nil {
		return 0, err
	}
	defer session.Close()

	var errBuf bytes.Buffer
	session.Stdout = stdout
	session.Stderr = io.MultiWriter(stderr, &errBuf)
	if stdin != nil {
		w, err := session.StdinPipe()
		if err != nil {
			return 0, err
		}
		go func() {
			_, _ = io.Copy(w, stdin)
			_ = w.Close()
		}()
	}

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		if err == nil {
			return 0, nil
		}
		var exitErr *ssh.ExitError
		if ok := errorAs(err, &exitErr); ok {
			return exitErr.ExitStatus(), nil
		}
		if errBuf.Len() > 0 {
			return 0, fmt.Errorf("%w: %s", err, strings.TrimSpace(errBuf.String()))
		}
		return 0, err
	case <-timer.C:
		_ = session.Signal(ssh.SIGKILL)
		return 0, fmt.Errorf("remote command timed out after %s", timeout)
	}
}

func errorAs(err error, target **ssh.ExitError) bool {
	if err == nil {
		return false
	}
	if v, ok := err.(*ssh.ExitError); ok {
		*target = v
		return true
	}
	return false
}

func posixDir(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		if i == 0 {
			return "/"
		}
		return path[:i]
	}
	return "."
}

func posixBase(path string) string {
	path = strings.TrimRight(path, "/")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: router-ssh [--host 192.168.3.1] [--port 222] [--user root] [--password keenetic] <command> [args]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  exec [--timeout 60s] <command>")
	fmt.Fprintln(w, "  upload [--mode 0755] <local> <remote>")
	fmt.Fprintln(w, "  download <remote> <local>")
	fmt.Fprintln(w, "  diagnose [--only accel,routing] [section ...]")
}
