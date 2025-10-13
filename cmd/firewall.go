package cmd

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/meimeitou/bgo/bpf/firewall"
	"github.com/spf13/cobra"
)

// Protocol conversion helpers
func protocolStringToNumber(protocol string) (uint8, error) {
	switch strings.ToLower(protocol) {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp":
		return 1, nil
	case "any", "":
		return 0, nil
	default:
		return 0, fmt.Errorf("invalid protocol: %s (supported: tcp, udp, icmp, any)", protocol)
	}
}

func protocolNumberToString(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 0:
		return "any"
	default:
		return fmt.Sprintf("unknown(%d)", protocol)
	}
}

// MakeFirewallServer creates the firewall-server command
func MakeFirewallServer() *cobra.Command {
	command := &cobra.Command{
		Use:   "firewall-server",
		Short: "Run unified XDP/TC firewall daemon with pinned maps",
		Long: `Run a unified eBPF firewall daemon that supports both XDP and TC-based filtering
with pinned maps for external interaction. The daemon provides REST APIs for managing
both XDP (whitelist/blacklist) and TC (ingress/egress) firewall rules and monitoring statistics.

The firewall uses pinned BPF maps that persist across program restarts,
allowing external tools to interact with the firewall configuration.

Both XDP and TC filtering modes are available simultaneously.`,
	}

	// Add subcommands
	command.AddCommand(makeFirewallStartCmd())
	command.AddCommand(makeFirewallCleanupMapsCmd())

	return command
}

// makeFirewallStartCmd creates the start subcommand for firewall-server
func makeFirewallStartCmd() *cobra.Command {
	var (
		interfaceName string
		listenAddr    string
		pinPath       string
	)

	command := &cobra.Command{
		Use:   "start",
		Short: "Start the firewall daemon",
		Long:  `Start the unified eBPF firewall daemon with REST API`,
		Example: `  # Start unified firewall server on eth0 with default settings
  bgo firewall-server start --interface eth0

  # Start with custom listen address and pin path
  bgo firewall-server start --interface eth0 --listen :8080 --pin-path /sys/fs/bpf/firewall

  # Configure via XDP API (whitelist/blacklist)
  curl -X POST http://localhost:8080/api/rules/whitelist \
    -H "Content-Type: application/json" \
    -d '{"ip_range":"192.168.1.0/24","port":22,"protocol":"tcp"}'

  # Configure via TC API (ingress/egress)
  curl -X POST http://localhost:8080/api/tc/rules/ingress \
    -H "Content-Type: application/json" \
    -d '{"ip_range":"192.168.1.100","port":22,"action":"deny"}'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFirewallServer(interfaceName, listenAddr, pinPath)
		},
	}

	command.Flags().StringVarP(&interfaceName, "interface", "i", "eth0", "Network interface to attach firewall")
	command.Flags().StringVar(&listenAddr, "listen", ":8080", "HTTP server listen address")
	command.Flags().StringVar(&pinPath, "pin-path", firewall.PinPath, "BPF filesystem pin path")

	return command
}

// makeFirewallCleanupMapsCmd creates the cleanup-maps subcommand
func makeFirewallCleanupMapsCmd() *cobra.Command {
	var (
		pinPath string
		force   bool
	)

	command := &cobra.Command{
		Use:   "cleanup-maps",
		Short: "Remove all pinned BPF maps",
		Long: `Remove all pinned BPF maps from the filesystem. This is useful when map specifications 
have changed and you need to recreate them with new parameters.

WARNING: This will remove all firewall configuration and statistics!`,
		Example: `  # Remove all pinned maps (will prompt for confirmation)
  bgo firewall-server cleanup-maps

  # Force cleanup without confirmation
  bgo firewall-server cleanup-maps --force

  # Cleanup maps from custom location
  bgo firewall-server cleanup-maps --pin-path /custom/path`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCleanupMaps(pinPath, force)
		},
	}

	command.Flags().StringVar(&pinPath, "pin-path", firewall.PinPath, "BPF filesystem pin path")
	command.Flags().BoolVar(&force, "force", false, "Force cleanup without confirmation")

	return command
}

// MakeFirewallUpdate creates the firewall-update command
func MakeFirewallUpdate() *cobra.Command {
	var (
		pinPath       string
		ruleType      string
		action        string
		ipRange       string
		port          uint16
		protocolStr   string
		ruleIndex     uint32
		xdp           bool
		ingress       bool
		egress        bool
		interfaceName string
	)

	command := &cobra.Command{
		Use:   "firewall-update",
		Short: "Update firewall rules via pinned maps",
		Long: `Update firewall rules by interacting with pinned BPF maps.
This command allows adding, removing, and listing firewall rules
without requiring the firewall daemon to be running.

Both XDP and TC modes support whitelist/blacklist rule types:
- Use --xdp to manage XDP rules (whitelist/blacklist)
- Use --ingress or --egress to manage TC rules (also supports whitelist/blacklist with --type)`,
		Example: `  # XDP Rules (whitelist/blacklist)
  # Add whitelist rule for SSH from local network
  bgo firewall-update --xdp --type whitelist --action add --ip 192.168.1.0/24 --port 22 --protocol tcp

  # Add blacklist rule to block all traffic from specific IP
  bgo firewall-update --xdp --type blacklist --action add --ip 10.0.0.100

  # List all XDP rules (both whitelist and blacklist)
  bgo firewall-update --xdp --action list

  # List specific XDP whitelist rules only
  bgo firewall-update --xdp --type whitelist --action list

  # List specific XDP blacklist rules only  
  bgo firewall-update --xdp --type blacklist --action list

  # Show XDP statistics
  bgo firewall-update --xdp --action stats

  # TC Rules (ingress/egress with whitelist/blacklist support)
  # Add TC whitelist rule to allow incoming SSH from specific IP 
  bgo firewall-update --action add --type whitelist --ip 192.168.1.100 --port 22 --protocol tcp --ingress

  # Add TC blacklist rule to block outgoing DNS to specific server
  bgo firewall-update --action add --type blacklist --ip 8.8.8.8 --port 53 --protocol udp --egress

  # List TC whitelist ingress rules
  bgo firewall-update --action list --type whitelist --ingress

  # List TC blacklist egress rules
  bgo firewall-update --action list --type blacklist --egress

  # Show TC statistics
  bgo firewall-update --action stats --ingress`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Convert protocol string to number
			protocol, err := protocolStringToNumber(protocolStr)
			if err != nil {
				return err
			}

			// Determine operation mode based on flags
			if xdp && (ingress || egress) {
				return fmt.Errorf("cannot specify --xdp with --ingress or --egress")
			}
			if ingress && egress {
				return fmt.Errorf("cannot specify both --ingress and --egress")
			}

			var direction string
			if xdp {
				direction = "xdp" // Use XDP mode (whitelist/blacklist)
			} else if ingress {
				direction = "ingress"
			} else if egress {
				direction = "egress"
			} else {
				// Default to XDP mode for backward compatibility
				direction = "xdp"
			}

			// Check if type was explicitly set by user
			typeExplicitlySet := cmd.Flags().Changed("type")

			return runFirewallUpdate(pinPath, ruleType, action, ipRange, port, protocol, ruleIndex, direction, typeExplicitlySet, interfaceName)
		},
	}

	command.Flags().StringVar(&pinPath, "pin-path", "/sys/fs/bpf/firewall", "BPF filesystem pin path")
	command.Flags().StringVar(&ruleType, "type", "whitelist", "Rule type: whitelist or blacklist (for both --xdp and TC modes)")
	command.Flags().StringVar(&action, "action", "list", "Action: add, remove, list, stats")
	command.Flags().StringVar(&ipRange, "ip", "", "IP address or CIDR range")
	command.Flags().Uint16Var(&port, "port", 0, "Port number (0 for any port)")
	command.Flags().StringVar(&protocolStr, "protocol", "any", "Protocol: tcp, udp, icmp, any")
	command.Flags().Uint32Var(&ruleIndex, "index", 0, "Rule index for remove action")
	command.Flags().BoolVar(&xdp, "xdp", false, "Manage XDP rules (whitelist/blacklist)")
	command.Flags().BoolVar(&ingress, "ingress", false, "Manage TC ingress (incoming) traffic rules")
	command.Flags().BoolVar(&egress, "egress", false, "Manage TC egress (outgoing) traffic rules")
	command.Flags().StringVarP(&interfaceName, "interface", "i", "eth0", "Network interface for TC program attachment (only used for TC rules)")

	return command
}

// FirewallServer represents the firewall daemon
type FirewallServer struct {
	fw        *firewall.XDPFirewall
	tcManager *firewall.TCFirewallManager
	server    *http.Server
	pinPath   string
}

// runFirewallServer starts the firewall daemon
func runFirewallServer(interfaceName, listenAddr, pinPath string) error {
	var fw *firewall.XDPFirewall
	var tcManager *firewall.TCFirewallManager
	var err error

	// Create XDP firewall instance with pin path
	fw, err = firewall.NewXDPFirewallWithPin(interfaceName, pinPath)
	if err != nil {
		return fmt.Errorf("failed to create XDP firewall: %v", err)
	}

	// Attach XDP firewall
	if err := fw.Attach(); err != nil {
		return fmt.Errorf("failed to attach XDP firewall: %v", err)
	}
	log.Printf("XDP Firewall attached to interface %s", interfaceName)

	// Create TC firewall manager with interface support
	tcManager = firewall.NewTCFirewallManagerWithInterface(interfaceName, pinPath)

	// Attach TC programs to the interface
	if err := tcManager.AttachPrograms(); err != nil {
		log.Printf("Warning: Failed to attach TC programs to interface %s: %v", interfaceName, err)
		log.Printf("TC rules will be configured but not enforced until programs are attached")
		log.Println("To attach TC programs manually:")
		log.Printf("  sudo tc qdisc add dev %s clsact", interfaceName)
		log.Printf("  sudo tc filter add dev %s ingress bpf obj firewall_tc_bpfel.o sec tc_ingress_filter direct-action", interfaceName)
		log.Printf("  sudo tc filter add dev %s egress bpf obj firewall_tc_bpfel.o sec tc_egress_filter direct-action", interfaceName)
	} else {
		log.Printf("TC Firewall programs attached to interface %s", interfaceName)
	}

	// Create server
	server := &FirewallServer{
		fw:        fw,
		tcManager: tcManager,
		pinPath:   pinPath,
	}

	// Ensure cleanup happens on any exit
	defer func() {
		if err := server.Cleanup(interfaceName); err != nil {
			log.Printf("Cleanup completed with errors: %v", err)
		}
	}()

	// Setup HTTP server
	mux := http.NewServeMux()
	server.setupRoutes(mux)

	httpServer := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}
	server.server = httpServer

	// Handle shutdown gracefully
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Received shutdown signal, shutting down firewall server...")
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}()

	// Start HTTP server
	log.Printf("Firewall server starting on %s", listenAddr)
	log.Printf("XDP and TC Firewall modes enabled for interface %s", interfaceName)
	log.Printf("BPF maps pinned to %s", pinPath)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
			cancel()
		}
	}()

	// Wait for shutdown
	<-ctx.Done()

	log.Println("Firewall server stopped")
	return nil
}

// Cleanup performs graceful cleanup of all BPF programs and resources
func (s *FirewallServer) Cleanup(interfaceName string) error {
	var errors []error

	log.Println("Starting firewall cleanup...")

	// Detach and cleanup XDP firewall
	if s.fw != nil {
		log.Printf("Detaching XDP program from interface %s...", interfaceName)
		if err := s.fw.Detach(); err != nil {
			log.Printf("Error detaching XDP program: %v", err)
			errors = append(errors, fmt.Errorf("XDP detach error: %v", err))
		} else {
			log.Printf("XDP program detached from interface %s", interfaceName)
		}

		if err := s.fw.Close(); err != nil {
			log.Printf("Error closing XDP firewall: %v", err)
			errors = append(errors, fmt.Errorf("XDP close error: %v", err))
		} else {
			log.Printf("XDP firewall resources cleaned up")
		}
	}

	// Detach and cleanup TC firewall
	if s.tcManager != nil {
		log.Printf("Detaching TC programs from interface %s...", interfaceName)
		if err := s.tcManager.DetachPrograms(); err != nil {
			log.Printf("Error detaching TC programs: %v", err)
			errors = append(errors, fmt.Errorf("TC detach error: %v", err))
		} else {
			log.Printf("TC programs detached from interface %s", interfaceName)
		}

		if err := s.tcManager.Close(); err != nil {
			log.Printf("Error closing TC firewall manager: %v", err)
			errors = append(errors, fmt.Errorf("TC close error: %v", err))
		} else {
			log.Printf("TC firewall manager resources cleaned up")
		}
	}

	log.Println("Firewall cleanup completed")

	if len(errors) > 0 {
		return fmt.Errorf("cleanup completed with %d errors: %v", len(errors), errors)
	}

	return nil
}

// setupRoutes configures HTTP routes
func (s *FirewallServer) setupRoutes(mux *http.ServeMux) {
	// XDP firewall routes
	mux.HandleFunc("/api/rules/whitelist", s.handleWhitelistRules)
	mux.HandleFunc("/api/rules/blacklist", s.handleBlacklistRules)
	mux.HandleFunc("/api/stats", s.handleStats)

	// TC firewall routes
	mux.HandleFunc("/api/tc/rules/ingress", s.handleTCIngressRules)
	mux.HandleFunc("/api/tc/rules/egress", s.handleTCEgressRules)
	mux.HandleFunc("/api/tc/stats", s.handleTCStats)

	// Common routes
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/health", s.handleHealth)
}

// Rule request/response structures
type RuleRequest struct {
	IPRange  string `json:"ip_range"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
}

type RuleResponse struct {
	Index    uint32 `json:"index"`
	IPStart  string `json:"ip_start"`
	IPEnd    string `json:"ip_end"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Action   uint8  `json:"action"`
}

type StatsResponse struct {
	TotalPackets    uint64 `json:"total_packets"`
	AllowedPackets  uint64 `json:"allowed_packets"`
	BlockedPackets  uint64 `json:"blocked_packets"`
	LvsDnatPackets  uint64 `json:"lvs_dnat_packets"`
	LvsSnatPackets  uint64 `json:"lvs_snat_packets"`
	LvsTotalPackets uint64 `json:"lvs_total_packets"`
}

// TC Rule request/response structures
type TCRuleRequest struct {
	IPRange string `json:"ip_range"`
	Port    uint16 `json:"port"`
	Action  string `json:"action"` // "allow" or "deny"
}

type TCRuleResponse struct {
	Index     uint32 `json:"index"`
	IPStart   string `json:"ip_start"`
	IPEnd     string `json:"ip_end"`
	Port      uint16 `json:"port"`
	Action    string `json:"action"`
	Direction string `json:"direction"`
}

type TCStatsResponse struct {
	TotalPackets   uint64 `json:"total_packets"`
	AllowedPackets uint64 `json:"allowed_packets"`
	DeniedPackets  uint64 `json:"denied_packets"`
	IngressPackets uint64 `json:"ingress_packets"`
	EgressPackets  uint64 `json:"egress_packets"`
}

// HTTP handlers
func (s *FirewallServer) handleWhitelistRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listRules(w, r, "whitelist")
	case http.MethodPost:
		s.addRule(w, r, "whitelist")
	case http.MethodDelete:
		s.removeRule(w, r, "whitelist")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *FirewallServer) handleBlacklistRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listRules(w, r, "blacklist")
	case http.MethodPost:
		s.addRule(w, r, "blacklist")
	case http.MethodDelete:
		s.removeRule(w, r, "blacklist")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *FirewallServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.fw.GetStats()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get stats: %v", err), http.StatusInternalServerError)
		return
	}

	response := StatsResponse{
		TotalPackets:    stats.TotalPackets,
		AllowedPackets:  stats.AllowedPackets,
		BlockedPackets:  stats.BlockedPackets,
		LvsDnatPackets:  stats.LvsDnatPackets,
		LvsSnatPackets:  stats.LvsSnatPackets,
		LvsTotalPackets: stats.LvsTotalPackets,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *FirewallServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement config management
	w.WriteHeader(http.StatusNotImplemented)
}

func (s *FirewallServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (s *FirewallServer) listRules(w http.ResponseWriter, r *http.Request, ruleType string) {
	var rules []firewall.Rule
	var err error

	if ruleType == "whitelist" {
		rules, err = s.fw.ListWhitelistRules()
	} else {
		rules, err = s.fw.ListBlacklistRules()
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list rules: %v", err), http.StatusInternalServerError)
		return
	}

	var response []RuleResponse
	for i, rule := range rules {
		response = append(response, RuleResponse{
			Index:    uint32(i),
			IPStart:  rule.IPStart.String(),
			IPEnd:    rule.IPEnd.String(),
			Port:     rule.Port,
			Protocol: protocolNumberToString(rule.Protocol),
			Action:   rule.Action,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *FirewallServer) addRule(w http.ResponseWriter, r *http.Request, ruleType string) {
	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Convert protocol string to number
	protocol, err := protocolStringToNumber(req.Protocol)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid protocol: %v", err), http.StatusBadRequest)
		return
	}

	// Parse IP range
	startIP, endIP, err := firewall.ParseCIDR(req.IPRange)
	if err != nil {
		// Try parsing as single IP
		ip := net.ParseIP(req.IPRange)
		if ip == nil {
			http.Error(w, "Invalid IP range", http.StatusBadRequest)
			return
		}
		startIP = ip
		endIP = ip
	}

	rule := firewall.Rule{
		IPStart:  startIP,
		IPEnd:    endIP,
		Port:     req.Port,
		Protocol: protocol,
		Action:   firewall.ActionAllow, // Default action for rules
	}

	if ruleType == "whitelist" {
		err = s.fw.AddWhitelistRule(rule)
	} else {
		err = s.fw.AddBlacklistRule(rule)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add rule: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "created"})
}

func (s *FirewallServer) removeRule(w http.ResponseWriter, r *http.Request, ruleType string) {
	indexStr := r.URL.Query().Get("index")
	if indexStr == "" {
		http.Error(w, "Missing index parameter", http.StatusBadRequest)
		return
	}

	index, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid index parameter", http.StatusBadRequest)
		return
	}

	if ruleType == "whitelist" {
		err = s.fw.RemoveWhitelistRule(uint32(index))
	} else {
		err = s.fw.RemoveBlacklistRule(uint32(index))
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove rule: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
}

// TC HTTP handlers
func (s *FirewallServer) handleTCIngressRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listTCRules(w, r, "ingress")
	case http.MethodPost:
		s.addTCRule(w, r, "ingress")
	case http.MethodDelete:
		s.removeTCRule(w, r, "ingress")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *FirewallServer) handleTCEgressRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listTCRules(w, r, "egress")
	case http.MethodPost:
		s.addTCRule(w, r, "egress")
	case http.MethodDelete:
		s.removeTCRule(w, r, "egress")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *FirewallServer) handleTCStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.tcManager.GetTCStats()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get TC stats: %v", err), http.StatusInternalServerError)
		return
	}

	response := TCStatsResponse{
		TotalPackets:   stats.TotalPackets,
		AllowedPackets: stats.AllowedPackets,
		DeniedPackets:  stats.DeniedPackets,
		IngressPackets: stats.IngressPackets,
		EgressPackets:  stats.EgressPackets,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *FirewallServer) listTCRules(w http.ResponseWriter, r *http.Request, direction string) {
	var rules []firewall.TCRule
	var err error

	if direction == "ingress" {
		rules, err = s.tcManager.ListIngressRules()
	} else {
		rules, err = s.tcManager.ListEgressRules()
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list TC rules: %v", err), http.StatusInternalServerError)
		return
	}

	var response []TCRuleResponse
	for i, rule := range rules {
		startIP := make(net.IP, 4)
		endIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(startIP, rule.IPStart)
		binary.BigEndian.PutUint32(endIP, rule.IPEnd)

		actionStr := "allow"
		if rule.Action == 1 {
			actionStr = "deny"
		}

		response = append(response, TCRuleResponse{
			Index:     uint32(i),
			IPStart:   startIP.String(),
			IPEnd:     endIP.String(),
			Port:      rule.Port,
			Action:    actionStr,
			Direction: direction,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *FirewallServer) addTCRule(w http.ResponseWriter, r *http.Request, direction string) {
	var req TCRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Parse IP range
	startIP, endIP, err := parseIPRange(req.IPRange)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid IP range: %v", err), http.StatusBadRequest)
		return
	}

	// Convert IPs to uint32 (network byte order)
	startIPBytes := startIP.To4()
	endIPBytes := endIP.To4()
	if startIPBytes == nil || endIPBytes == nil {
		http.Error(w, "Only IPv4 addresses are supported", http.StatusBadRequest)
		return
	}

	startIPUint32 := binary.BigEndian.Uint32(startIPBytes)
	endIPUint32 := binary.BigEndian.Uint32(endIPBytes)

	// Parse action
	action := uint8(0) // ALLOW by default
	if req.Action == "deny" {
		action = 1
	}

	rule := firewall.TCRule{
		IPStart: startIPUint32,
		IPEnd:   endIPUint32,
		Port:    req.Port,
		Action:  action,
		Direction: func() uint8 {
			if direction == "ingress" {
				return 0
			} else {
				return 1
			}
		}(),
	}

	if direction == "ingress" {
		err = s.tcManager.AddIngressRule(rule)
	} else {
		err = s.tcManager.AddEgressRule(rule)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add TC rule: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "created"})
}

func (s *FirewallServer) removeTCRule(w http.ResponseWriter, r *http.Request, direction string) {
	indexStr := r.URL.Query().Get("index")
	if indexStr == "" {
		http.Error(w, "Missing index parameter", http.StatusBadRequest)
		return
	}

	index, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid index parameter", http.StatusBadRequest)
		return
	}

	if direction == "ingress" {
		err = s.tcManager.RemoveIngressRule(uint32(index))
	} else {
		err = s.tcManager.RemoveEgressRule(uint32(index))
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to remove TC rule: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "removed"})
}

// runFirewallUpdate handles the firewall-update command
func runFirewallUpdate(pinPath, ruleType, action, ipRange string, port uint16, protocol uint8, ruleIndex uint32, direction string, typeExplicitlySet bool, interfaceName string) error {
	if direction == "ingress" || direction == "egress" {
		return runTCFirewallUpdate(pinPath, ruleType, direction, action, ipRange, port, protocol, ruleIndex, typeExplicitlySet, interfaceName)
	}

	// Handle XDP-based rules (whitelist/blacklist)
	if direction == "xdp" || direction == "" {
		// direction == "" for backward compatibility
		fwManager := firewall.NewFirewallManager(pinPath)

		switch action {
		case "add":
			if ipRange == "" {
				return fmt.Errorf("IP range is required for add action")
			}

			// Parse IP range
			startIP, endIP, err := firewall.ParseCIDR(ipRange)
			if err != nil {
				// Try parsing as single IP
				ip := net.ParseIP(ipRange)
				if ip == nil {
					return fmt.Errorf("invalid IP range: %s", ipRange)
				}
				startIP = ip
				endIP = ip
			}

			rule := firewall.Rule{
				IPStart:  startIP,
				IPEnd:    endIP,
				Port:     port,
				Protocol: protocol,
				Action:   firewall.ActionAllow, // Default action for rules
			}

			if ruleType == "whitelist" {
				err = fwManager.AddWhitelistRule(rule)
			} else if ruleType == "blacklist" {
				err = fwManager.AddBlacklistRule(rule)
			} else {
				return fmt.Errorf("invalid rule type: %s (must be whitelist or blacklist)", ruleType)
			}

			if err != nil {
				return fmt.Errorf("failed to add rule: %v", err)
			}

			fmt.Printf("Successfully added %s rule for %s\n", ruleType, ipRange)

		case "remove":
			var err error
			if ruleType == "whitelist" {
				err = fwManager.RemoveWhitelistRule(ruleIndex)
			} else if ruleType == "blacklist" {
				err = fwManager.RemoveBlacklistRule(ruleIndex)
			} else {
				return fmt.Errorf("invalid rule type: %s (must be whitelist or blacklist)", ruleType)
			}

			if err != nil {
				return fmt.Errorf("failed to remove rule: %v", err)
			}

			fmt.Printf("Successfully removed %s rule at index %d\n", ruleType, ruleIndex)

		case "list":
			// Check if type was explicitly specified via command line flag
			// If user runs with default type, show all rules; if explicitly specified, show only that type
			showAllRules := ruleType == "whitelist" && !typeExplicitlySet

			if showAllRules {
				// List both whitelist and blacklist rules
				whitelistRules, err := fwManager.ListWhitelistRules()
				if err != nil {
					return fmt.Errorf("failed to list whitelist rules: %v", err)
				}

				blacklistRules, err := fwManager.ListBlacklistRules()
				if err != nil {
					return fmt.Errorf("failed to list blacklist rules: %v", err)
				}

				// Print whitelist rules
				if len(whitelistRules) > 0 {
					fmt.Printf("Whitelist Rules:\n")
					fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
					fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")

					for i, rule := range whitelistRules {
						fmt.Printf("%-5d %-15s %-15s %-6d %-8s %-6d\n",
							i,
							rule.IPStart.String(),
							rule.IPEnd.String(),
							rule.Port,
							protocolNumberToString(rule.Protocol),
							rule.Action)
					}
					fmt.Println()
				} else {
					fmt.Printf("Whitelist Rules:\n")
					fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
					fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")
					fmt.Println("No whitelist rules found")
					fmt.Println()
				}

				// Print blacklist rules
				if len(blacklistRules) > 0 {
					fmt.Printf("Blacklist Rules:\n")
					fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
					fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")

					for i, rule := range blacklistRules {
						fmt.Printf("%-5d %-15s %-15s %-6d %-8s %-6d\n",
							i,
							rule.IPStart.String(),
							rule.IPEnd.String(),
							rule.Port,
							protocolNumberToString(rule.Protocol),
							rule.Action)
					}
				} else {
					fmt.Printf("Blacklist Rules:\n")
					fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
					fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")
					fmt.Println("No blacklist rules found")
				}
			} else {
				// Show specific rule type as requested
				var rules []firewall.Rule
				var err error

				if ruleType == "whitelist" {
					rules, err = fwManager.ListWhitelistRules()
				} else if ruleType == "blacklist" {
					rules, err = fwManager.ListBlacklistRules()
				} else {
					return fmt.Errorf("invalid rule type: %s (must be whitelist or blacklist)", ruleType)
				}

				if err != nil {
					return fmt.Errorf("failed to list rules: %v", err)
				}

				fmt.Printf("%s Rules:\n", ruleType)
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")

				for i, rule := range rules {
					fmt.Printf("%-5d %-15s %-15s %-6d %-8s %-6d\n",
						i,
						rule.IPStart.String(),
						rule.IPEnd.String(),
						rule.Port,
						protocolNumberToString(rule.Protocol),
						rule.Action)
				}
			}

		case "stats":
			stats, err := fwManager.GetStats()
			if err != nil {
				return fmt.Errorf("failed to get stats: %v", err)
			}

			fmt.Printf("Firewall Statistics:\n")
			fmt.Printf("Total Packets:   %d\n", stats.TotalPackets)
			fmt.Printf("Allowed Packets: %d\n", stats.AllowedPackets)
			fmt.Printf("Blocked Packets: %d\n", stats.BlockedPackets)
			if stats.TotalPackets > 0 {
				fmt.Printf("Allow Rate:      %.2f%%\n", float64(stats.AllowedPackets)/float64(stats.TotalPackets)*100)
				fmt.Printf("Block Rate:      %.2f%%\n", float64(stats.BlockedPackets)/float64(stats.TotalPackets)*100)
			}

			// Display LVS statistics
			fmt.Printf("\nLVS Statistics:\n")
			fmt.Printf("LVS Total Packets: %d\n", stats.LvsTotalPackets)
			fmt.Printf("DNAT Packets:      %d\n", stats.LvsDnatPackets)
			fmt.Printf("SNAT Packets:      %d\n", stats.LvsSnatPackets)
			if stats.LvsTotalPackets > 0 {
				fmt.Printf("DNAT Rate:         %.2f%%\n", float64(stats.LvsDnatPackets)/float64(stats.LvsTotalPackets)*100)
				fmt.Printf("SNAT Rate:         %.2f%%\n", float64(stats.LvsSnatPackets)/float64(stats.LvsTotalPackets)*100)
			}

		default:
			return fmt.Errorf("invalid action: %s (must be add, remove, list, or stats)", action)
		}

		return nil
	}

	return fmt.Errorf("invalid direction: %s (must be xdp, ingress, or egress)", direction)
}

// runTCFirewallUpdate handles TC-based firewall rules with whitelist/blacklist support
func runTCFirewallUpdate(pinPath, ruleType, direction, action, ipRange string, port uint16, protocol uint8, ruleIndex uint32, typeExplicitlySet bool, interfaceName string) error {
	fmt.Printf("Managing TC %s rules\n", direction)

	// Create TC manager with interface support
	tcManager := firewall.NewTCFirewallManagerWithInterface(interfaceName, pinPath)

	// Check if TC programs are attached
	attached, err := tcManager.IsAttached()
	if err != nil {
		fmt.Printf("Warning: Cannot check TC attachment status: %v\n", err)
	} else if !attached {
		fmt.Printf("Warning: TC firewall programs are not attached to interface %s\n", interfaceName)
		return fmt.Errorf("TC programs are not attached to interface %s", interfaceName)
	}

	switch action {
	case "add":
		if ipRange == "" {
			return fmt.Errorf("IP range is required for add action")
		}

		// Parse IP range to get start and end IPs
		startIP, endIP, err := parseIPRange(ipRange)
		if err != nil {
			return fmt.Errorf("invalid IP range: %v", err)
		}

		// Convert IPs to uint32 (network byte order)
		startIPBytes := startIP.To4()
		endIPBytes := endIP.To4()
		if startIPBytes == nil || endIPBytes == nil {
			return fmt.Errorf("only IPv4 addresses are supported")
		}

		startIPUint32 := binary.BigEndian.Uint32(startIPBytes)
		endIPUint32 := binary.BigEndian.Uint32(endIPBytes)

		// Create TC rule
		rule := firewall.TCRule{
			IPStart:  startIPUint32,
			IPEnd:    endIPUint32,
			Port:     port,
			Protocol: protocol,
		}

		var directionFlag uint8
		if direction == "ingress" {
			directionFlag = firewall.TCDirectionIngress
		} else {
			directionFlag = firewall.TCDirectionEgress
		}

		// Add rule based on type
		if ruleType == "whitelist" {
			rule.RuleType = firewall.TCRuleTypeWhitelist
			rule.Action = firewall.TCActionAllow
			if err := tcManager.AddWhitelistRule(rule, directionFlag); err != nil {
				return fmt.Errorf("failed to add TC whitelist rule: %v", err)
			}
			fmt.Printf("Successfully added %s whitelist rule for %s", direction, ipRange)
		} else if ruleType == "blacklist" {
			rule.RuleType = firewall.TCRuleTypeBlacklist
			rule.Action = firewall.TCActionDeny
			if err := tcManager.AddBlacklistRule(rule, directionFlag); err != nil {
				return fmt.Errorf("failed to add TC blacklist rule: %v", err)
			}
			fmt.Printf("Successfully added %s blacklist rule for %s", direction, ipRange)
		} else {
			return fmt.Errorf("invalid rule type: %s (must be whitelist or blacklist)", ruleType)
		}
		if port > 0 {
			fmt.Printf(":%d", port)
		}
		if protocol > 0 {
			protocolName := map[uint8]string{
				1:  "ICMP",
				6:  "TCP",
				17: "UDP",
			}[protocol]
			if protocolName != "" {
				fmt.Printf(" (%s)", protocolName)
			} else {
				fmt.Printf(" (protocol %d)", protocol)
			}
		}
		fmt.Println()

	case "remove":
		var directionFlag uint8
		if direction == "ingress" {
			directionFlag = firewall.TCDirectionIngress
		} else {
			directionFlag = firewall.TCDirectionEgress
		}

		// Remove rule based on type
		if ruleType == "whitelist" {
			if err := tcManager.RemoveWhitelistRule(ruleIndex, directionFlag); err != nil {
				return fmt.Errorf("failed to remove TC whitelist rule: %v", err)
			}
			fmt.Printf("Successfully removed %s whitelist rule at index %d\n", direction, ruleIndex)
		} else if ruleType == "blacklist" {
			if err := tcManager.RemoveBlacklistRule(ruleIndex, directionFlag); err != nil {
				return fmt.Errorf("failed to remove TC blacklist rule: %v", err)
			}
			fmt.Printf("Successfully removed %s blacklist rule at index %d\n", direction, ruleIndex)
		} else {
			return fmt.Errorf("invalid rule type: %s (must be whitelist or blacklist)", ruleType)
		}

	case "list":
		var directionFlag uint8
		if direction == "ingress" {
			directionFlag = firewall.TCDirectionIngress
		} else {
			directionFlag = firewall.TCDirectionEgress
		}

		// Check if type was explicitly specified via command line flag
		// If user runs with default type, show all rules; if explicitly specified, show only that type
		showAllRules := ruleType == "whitelist" && !typeExplicitlySet

		if showAllRules {
			// List both whitelist and blacklist rules
			whitelistRules, err := tcManager.ListWhitelistRules(directionFlag)
			if err != nil {
				return fmt.Errorf("failed to list TC whitelist rules: %v", err)
			}

			blacklistRules, err := tcManager.ListBlacklistRules(directionFlag)
			if err != nil {
				return fmt.Errorf("failed to list TC blacklist rules: %v", err)
			}

			fmt.Printf("TC %s Rules:\n", direction)

			// Print whitelist rules
			if len(whitelistRules) > 0 {
				fmt.Printf("\nWhitelist Rules:\n")
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")

				for i, rule := range whitelistRules {
					startIP := make(net.IP, 4)
					endIP := make(net.IP, 4)
					binary.BigEndian.PutUint32(startIP, rule.IPStart)
					binary.BigEndian.PutUint32(endIP, rule.IPEnd)

					protocolName := protocolNumberToString(rule.Protocol)
					actionName := map[uint8]string{0: "ALLOW", 1: "DENY"}[rule.Action]

					fmt.Printf("%-5d %-15s %-15s %-6d %-8s %-6s\n",
						i,
						startIP.String(),
						endIP.String(),
						rule.Port,
						protocolName,
						actionName)
				}
				fmt.Println()
			} else {
				fmt.Printf("\nWhitelist Rules:\n")
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")
				fmt.Println("No whitelist rules found")
				fmt.Println()
			}

			// Print blacklist rules
			if len(blacklistRules) > 0 {
				fmt.Printf("Blacklist Rules:\n")
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")

				for i, rule := range blacklistRules {
					startIP := make(net.IP, 4)
					endIP := make(net.IP, 4)
					binary.BigEndian.PutUint32(startIP, rule.IPStart)
					binary.BigEndian.PutUint32(endIP, rule.IPEnd)

					protocolName := protocolNumberToString(rule.Protocol)
					actionName := map[uint8]string{0: "ALLOW", 1: "DENY"}[rule.Action]

					fmt.Printf("%-5d %-15s %-15s %-6d %-8s %-6s\n",
						i,
						startIP.String(),
						endIP.String(),
						rule.Port,
						protocolName,
						actionName)
				}
			} else {
				fmt.Printf("Blacklist Rules:\n")
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
				fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")
				fmt.Println("No blacklist rules found")
			}
		} else {
			// Show specific rule type as requested
			var rules []firewall.TCRule
			var err error

			if ruleType == "whitelist" {
				rules, err = tcManager.ListWhitelistRules(directionFlag)
			} else if ruleType == "blacklist" {
				rules, err = tcManager.ListBlacklistRules(directionFlag)
			} else {
				return fmt.Errorf("invalid rule type: %s (must be whitelist or blacklist)", ruleType)
			}

			if err != nil {
				return fmt.Errorf("failed to list TC %s rules: %v", ruleType, err)
			}

			fmt.Printf("TC %s %s Rules:\n", direction, ruleType)
			fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "Index", "IP Start", "IP End", "Port", "Protocol", "Action")
			fmt.Printf("%-5s %-15s %-15s %-6s %-8s %-6s\n", "-----", "--------", "------", "----", "--------", "------")

			for i, rule := range rules {
				startIP := make(net.IP, 4)
				endIP := make(net.IP, 4)
				binary.BigEndian.PutUint32(startIP, rule.IPStart)
				binary.BigEndian.PutUint32(endIP, rule.IPEnd)

				protocolName := protocolNumberToString(rule.Protocol)
				actionName := map[uint8]string{0: "ALLOW", 1: "DENY"}[rule.Action]

				fmt.Printf("%-5d %-15s %-15s %-6d %-8s %-6s\n",
					i,
					startIP.String(),
					endIP.String(),
					rule.Port,
					protocolName,
					actionName)
			}

			if len(rules) == 0 {
				fmt.Printf("No %s rules found\n", ruleType)
			}
		}

	case "stats":
		stats, err := tcManager.GetTCStats()
		if err != nil {
			return fmt.Errorf("failed to get TC stats: %v", err)
		}

		fmt.Printf("TC Firewall Statistics:\n")
		fmt.Printf("Total Packets:   %d\n", stats.TotalPackets)
		fmt.Printf("Allowed Packets: %d\n", stats.AllowedPackets)
		fmt.Printf("Denied Packets:  %d\n", stats.DeniedPackets)
		fmt.Printf("Ingress Packets: %d\n", stats.IngressPackets)
		fmt.Printf("Egress Packets:  %d\n", stats.EgressPackets)
		if stats.TotalPackets > 0 {
			fmt.Printf("Allow Rate:      %.2f%%\n", float64(stats.AllowedPackets)/float64(stats.TotalPackets)*100)
			fmt.Printf("Deny Rate:       %.2f%%\n", float64(stats.DeniedPackets)/float64(stats.TotalPackets)*100)
		}

	default:
		return fmt.Errorf("invalid action: %s (must be add, remove, list, or stats)", action)
	}

	return nil
}

// TC Rule structures for backward compatibility
type TCRule struct {
	IPStart   uint32
	IPEnd     uint32
	Port      uint16
	Action    uint8
	Direction uint8
}

type TCStats struct {
	TotalPackets   uint64
	AllowedPackets uint64
	DeniedPackets  uint64
	IngressPackets uint64
	EgressPackets  uint64
}

// parseIPRange parses an IP range (single IP or CIDR) and returns start and end IPs
func parseIPRange(ipRange string) (net.IP, net.IP, error) {
	// First try to parse as CIDR
	if strings.Contains(ipRange, "/") {
		return firewall.ParseCIDR(ipRange)
	}

	// Parse as single IP
	ip := net.ParseIP(ipRange)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid IP address: %s", ipRange)
	}
	return ip, ip, nil
}

// runCleanupMaps removes all pinned BPF maps
func runCleanupMaps(pinPath string, force bool) error {
	// List of known firewall map names including TC maps
	mapNames := []string{
		// XDP firewall maps
		"whitelist_map",
		"blacklist_map",
		"stats_map",
		"config_map",
		// LVS maps
		"lvs_dnat_map",
		"conn_track_map",
		"backend_map",
		"service_map",
		// TC firewall maps
		"tc_ingress_whitelist",
		"tc_ingress_whitelist_count",
		"tc_ingress_blacklist",
		"tc_ingress_blacklist_count",
		"tc_egress_whitelist",
		"tc_egress_whitelist_count",
		"tc_egress_blacklist",
		"tc_egress_blacklist_count",
		"tc_stats_map",
	}

	if !force {
		fmt.Printf("WARNING: This will remove all pinned BPF maps and firewall configuration!\n")
		fmt.Printf("Maps to be removed from %s:\n", pinPath)
		for _, mapName := range mapNames {
			mapPath := filepath.Join(pinPath, mapName)
			if _, err := os.Stat(mapPath); err == nil {
				fmt.Printf("  - %s\n", mapPath)
			}
		}
		fmt.Printf("\nAre you sure you want to continue? (y/N): ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %v", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Operation cancelled")
			return nil
		}
	}

	removedCount := 0
	for _, mapName := range mapNames {
		mapPath := filepath.Join(pinPath, mapName)

		// Check if map exists
		if _, err := os.Stat(mapPath); os.IsNotExist(err) {
			continue
		}

		// Remove the pinned map
		err := os.Remove(mapPath)
		if err != nil {
			fmt.Printf("Warning: failed to remove %s: %v\n", mapPath, err)
			continue
		}

		fmt.Printf("Removed: %s\n", mapPath)
		removedCount++
	}

	if removedCount == 0 {
		fmt.Printf("No maps found to remove in %s\n", pinPath)
	} else {
		fmt.Printf("Successfully removed %d BPF maps\n", removedCount)
		fmt.Printf("You can now restart the firewall to recreate maps with new specifications\n")
	}

	return nil
}
