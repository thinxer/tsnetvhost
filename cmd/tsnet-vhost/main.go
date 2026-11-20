package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tsnetvhost/internal/backend"
	"tsnetvhost/internal/vhostuser"
)

type options struct {
	name        string
	controlURL  string
	stateDir    string
	socket      string
	statusFile  string
	authKeyFile string
	exitNode    string
	mtu         int
	logLevel    string
}

func main() {
	if err := run(); err != nil {
		log.Printf("tsnet-vhost: %v", err)
		os.Exit(1)
	}
}

func run() (runErr error) {
	var opts options
	flag.StringVar(&opts.name, "name", "", "VM and tsnet node name")
	flag.StringVar(&opts.controlURL, "control-url", "https://controlplane.tailscale.com", "Tailscale or Headscale control URL")
	flag.StringVar(&opts.stateDir, "state-dir", "", "persistent state directory")
	flag.StringVar(&opts.socket, "socket", "", "vhost-user Unix socket")
	flag.StringVar(&opts.statusFile, "status-file", "", "status JSON path")
	flag.StringVar(&opts.authKeyFile, "auth-key-file", "", "optional authentication key file")
	flag.StringVar(&opts.exitNode, "exit-node", "", "stable node ID of required exit node")
	flag.IntVar(&opts.mtu, "mtu", backend.DefaultMTU, "guest and tunnel MTU")
	flag.StringVar(&opts.logLevel, "log-level", "info", "log level: info or debug")
	flag.Parse()
	if err := validateOptions(&opts); err != nil {
		return err
	}
	backend.SetDebug(opts.logLevel == "debug")
	endpoint, err := vhostuser.NewEndpoint()
	if err != nil {
		return err
	}
	defer endpoint.Close()
	device := backend.NewDevice(opts.name, opts.mtu, endpoint)
	writer, err := backend.NewStatusWriter(opts.statusFile, opts.name, opts.socket, device.MACString(), opts.mtu)
	if err != nil {
		return err
	}
	writer.SetExitNode(opts.exitNode, false)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer func() {
		if runErr != nil {
			_ = writer.Publish("failed", nil, runErr)
		} else {
			_ = writer.Publish("stopped", nil, nil)
		}
	}()
	authKey := ""
	if opts.authKeyFile != "" {
		data, err := os.ReadFile(opts.authKeyFile)
		if err != nil {
			return err
		}
		authKey = strings.TrimSpace(string(data))
	}
	server := &tsnet.Server{
		Hostname:   opts.name,
		Dir:        opts.stateDir,
		ControlURL: opts.controlURL,
		AuthKey:    authKey,
		Tun:        device,
		Logf:       log.Printf,
	}
	defer server.Close()
	if err := writer.Publish("registering", nil, nil); err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	client, err := server.LocalClient()
	if err != nil {
		return err
	}
	if opts.exitNode != "" {
		_, err = client.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs:         ipn.Prefs{ExitNodeID: tailcfg.StableNodeID(opts.exitNode)},
			ExitNodeIDSet: true,
		})
		if err != nil {
			return err
		}
	}
	ipv4, ipv6, dns, err := waitNetwork(ctx, client, writer, opts.exitNode)
	if err != nil {
		return err
	}
	device.SetAddresses(ipv4, ipv6)
	writer.SetNetwork(addressStrings(ipv4, ipv6), dns)
	log.Printf("%s: addresses=%s socket=%s", opts.name, strings.Join(addressStrings(ipv4, ipv6), ","), opts.socket)
	return endpoint.Serve(ctx, opts.socket, device.Config, vhostuser.Hooks{
		OnListening: func() {
			if err := writer.Publish("ready", nil, nil); err != nil {
				log.Printf("status update failed: %v", err)
				stop()
			}
		},
		OnConnectionChange: func(connected bool) {
			if err := writer.Publish("ready", &connected, nil); err != nil {
				log.Printf("status update failed: %v", err)
				stop()
			}
		},
	})
}

func validateOptions(opts *options) error {
	if opts.name == "" || strings.ContainsAny(opts.name, "/\\") {
		return fmt.Errorf("--name is required and must not contain path separators")
	}
	if opts.mtu < 576 || opts.mtu > 9000 {
		return fmt.Errorf("--mtu must be between 576 and 9000")
	}
	if opts.logLevel != "info" && opts.logLevel != "debug" {
		return fmt.Errorf("--log-level must be info or debug")
	}
	if opts.stateDir == "" {
		opts.stateDir = filepath.Join(xdgStateHome(), "tsnet-vhost", opts.name)
	}
	if opts.socket == "" {
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			opts.socket = filepath.Join(runtimeDir, "tsnet-vhost", opts.name+".sock")
		} else {
			opts.socket = filepath.Join(opts.stateDir, "vhost.sock")
		}
	}
	if opts.statusFile == "" {
		opts.statusFile = filepath.Join(opts.stateDir, "status.json")
	}
	if err := os.MkdirAll(opts.stateDir, 0o700); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Dir(opts.socket), 0o700)
}

func xdgStateHome() string {
	if directory := os.Getenv("XDG_STATE_HOME"); directory != "" {
		return directory
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".local/state"
	}
	return filepath.Join(home, ".local", "state")
}

func waitNetwork(ctx context.Context, client *local.Client, writer *backend.StatusWriter, exitNode string) (netip.Addr, netip.Addr, []string, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	availableReported := false
	for {
		status, err := client.Status(ctx)
		if err == nil && status.Self != nil {
			var ipv4, ipv6 netip.Addr
			for _, address := range status.Self.TailscaleIPs {
				if address.Is4() {
					ipv4 = address
				} else if address.Is6() {
					ipv6 = address
				}
			}
			available := exitAvailable(status.Peer, exitNode)
			if exitNode != "" && available != availableReported {
				writer.SetExitNode(exitNode, available)
				availableReported = available
			}
			if ipv6.IsValid() && available {
				dns, err := controlDNS(ctx, client, ipv4, ipv6)
				return ipv4, ipv6, dns, err
			}
		}
		select {
		case <-ctx.Done():
			return netip.Addr{}, netip.Addr{}, nil, fmt.Errorf("waiting for tsnet addresses: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func exitAvailable(peers map[key.NodePublic]*ipnstate.PeerStatus, exitNode string) bool {
	if exitNode == "" {
		return true
	}
	for _, peer := range peers {
		if peer.ID == tailcfg.StableNodeID(exitNode) {
			return peer.Online && peer.ExitNodeOption
		}
	}
	return false
}

func controlDNS(ctx context.Context, client *local.Client, ipv4, ipv6 netip.Addr) ([]string, error) {
	config, err := client.DNSConfig(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var addresses []string
	if config.Proxied {
		if ipv4.IsValid() {
			addresses = append(addresses, "100.100.100.100")
			seen["100.100.100.100"] = true
		}
		if ipv6.IsValid() {
			addresses = append(addresses, "fd7a:115c:a1e0::53")
			seen["fd7a:115c:a1e0::53"] = true
		}
	}
	resolvers := config.Resolvers
	if len(resolvers) == 0 {
		resolvers = config.FallbackResolvers
	}
	for _, resolver := range resolvers {
		address, err := netip.ParseAddr(resolver.Addr)
		if err == nil && !seen[address.String()] {
			seen[address.String()] = true
			addresses = append(addresses, address.String())
		}
	}
	for _, address := range config.Nameservers {
		if !seen[address.String()] {
			seen[address.String()] = true
			addresses = append(addresses, address.String())
		}
	}
	if addresses == nil {
		addresses = []string{}
	}
	return addresses, nil
}

func addressStrings(ipv4, ipv6 netip.Addr) []string {
	addresses := []string{}
	if ipv4.IsValid() {
		addresses = append(addresses, ipv4.String()+"/32")
	}
	if ipv6.IsValid() {
		addresses = append(addresses, ipv6.String()+"/128")
	}
	return addresses
}
