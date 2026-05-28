package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"nfqws2strategy/internal/app"
	"nfqws2strategy/internal/catalog"
	"nfqws2strategy/internal/config"
	"nfqws2strategy/internal/engine"
	"nfqws2strategy/internal/probe"
	"nfqws2strategy/internal/server"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// repo is the GitHub owner/name used for self-update checks and downloads.
var repo = "Omn1z/nfqws2-keenetic-strategy-selector"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println(version)
	case "serve":
		cmdServe(os.Args[2:])
	case "selftest":
		cmdSelftest(os.Args[2:])
	case "config":
		cmdConfig()
	case "checkupdate":
		cmdCheckUpdate()
	case "update":
		cmdUpdate()
	default:
		usage()
		os.Exit(2)
	}
}

func cmdCheckUpdate() {
	a, err := app.New(loadConfig())
	if err != nil {
		log.Fatalln("init:", err)
	}
	info, err := a.CheckUpdate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "check failed:", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}

func cmdUpdate() {
	a, err := app.New(loadConfig())
	if err != nil {
		log.Fatalln("init:", err)
	}
	info, err := a.SelfUpdate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "update failed:", err)
		os.Exit(1)
	}
	fmt.Printf("updating %s -> %s; service will restart\n", info.Current, info.Latest)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  nfqws2-strategy serve [-l <addr>]                                run web UI + API (default :8090)")
	fmt.Fprintln(os.Stderr, "  nfqws2-strategy selftest [-s <strategyIndex>] <host> [host...]   run one strategy against hosts, print JSON")
	fmt.Fprintln(os.Stderr, "  nfqws2-strategy config                                          print resolved config")
	fmt.Fprintln(os.Stderr, "  nfqws2-strategy checkupdate                                     check GitHub for a newer release")
	fmt.Fprintln(os.Stderr, "  nfqws2-strategy update                                          download the latest release and restart")
}

func cmdServe(args []string) {
	cfg := loadConfig()
	daemon := false
	logPath, pidPath := "", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-l":
			if i+1 < len(args) {
				cfg.ListenAddr = args[i+1]
				i++
			}
		case "-d":
			daemon = true
		case "-log":
			if i+1 < len(args) {
				logPath = args[i+1]
				i++
			}
		case "-pid":
			if i+1 < len(args) {
				pidPath = args[i+1]
				i++
			}
		}
	}
	if daemon {
		isParent, err := maybeDaemonize(logPath, pidPath)
		if err != nil {
			log.Fatalln("daemonize:", err)
		}
		if isParent {
			return
		}
	}

	a, err := app.New(cfg)
	if err != nil {
		log.Fatalln("init:", err)
	}
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: server.New(a).Handler()}

	go func() {
		log.Printf("nfqws2-strategy %s listening on %s (data: %s)", version, cfg.ListenAddr, cfg.DataDir)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalln("serve:", err)
		}
	}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	<-sigc
	log.Println("shutting down...")
	a.Shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func loadConfig() *config.Config {
	cfg := config.Default()
	if err := cfg.LoadFromNfqws2Conf(); err != nil {
		fmt.Fprintf(os.Stderr, "warn: could not read %s: %v (using defaults)\n", cfg.Nfqws2Conf, err)
	}
	if v := os.Getenv("N2S_DATA"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("N2S_LISTEN"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("N2S_INIT"); v != "" {
		cfg.InitScript = v
	}
	cfg.Version = version
	cfg.Repo = repo
	return cfg
}

func cmdConfig() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(loadConfig())
}

func cmdSelftest(args []string) {
	stratIdx := 0
	var hosts []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-s" && i+1 < len(args) {
			stratIdx, _ = strconv.Atoi(args[i+1])
			i++
			continue
		}
		hosts = append(hosts, args[i])
	}
	if len(hosts) == 0 {
		usage()
		os.Exit(2)
	}

	cfg := loadConfig()
	cat := catalog.Builtin()
	if stratIdx < 0 || stratIdx >= len(cat) {
		fmt.Fprintf(os.Stderr, "strategy index out of range (0..%d)\n", len(cat)-1)
		os.Exit(2)
	}
	strat := cat[stratIdx]

	sb := engine.NewSandbox(cfg, 0)
	if err := sb.RulesUp(); err != nil {
		fmt.Fprintln(os.Stderr, "rules up:", err)
		os.Exit(1)
	}
	// Always clean up, even on Ctrl-C.
	cleanup := func() {
		sb.StopNfqws()
		sb.RulesDown()
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		cleanup()
		os.Exit(130)
	}()
	defer cleanup()

	if err := sb.StartNfqws(nil, strat.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "start nfqws:", err)
		os.Exit(1)
	}

	pr := probe.New(sb.PortLo, sb.PortHi)
	results := make([]probe.Result, 0, len(hosts))
	for _, h := range hosts {
		results = append(results, pr.Probe(context.Background(), h))
	}

	out := map[string]any{
		"strategy": strat,
		"queue":    sb.QNum,
		"ports":    fmt.Sprintf("%d-%d", sb.PortLo, sb.PortHi),
		"results":  results,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
