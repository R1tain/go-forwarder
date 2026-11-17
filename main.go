package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Rule struct {
	ID           int    `json:"id"`
	Remark       string `json:"remark"`
	ListenFamily string `json:"listen_family"` // "ipv4", "ipv6", "dual", or ""
	ListenIP     string `json:"listen_ip"`
	ListenPort   int    `json:"listen_port"`
	Protocol     string `json:"protocol"` // "tcp", "udp", "both", "all", "tcp+udp"
	Target       string `json:"target"`
	TargetPort   int    `json:"target_port"`
	TargetFamily string `json:"target_family,omitempty"` // "ipv6", "ipv4", "auto", "follow"
	Enabled      bool   `json:"enabled"`
	Created      string `json:"created,omitempty"`
}

const (
	maxUDPSessions      = 4096
	udpSessionTimeout   = 60 * time.Second
	udpCleanupInterval  = 10 * time.Second
	udpBufferSize       = 65535
	tcpHalfCloseTimeout = 30 * time.Second
	maxTCPConnections   = 10000
)

var (
	connID atomic.Uint64
	tcpSem = make(chan struct{}, maxTCPConnections)
)

// selectIP selects preferred IP matching targetFamily and listenFamily
func selectIP(ips []net.IP, targetFamily, listenFamily string) net.IP {
	if len(ips) == 0 {
		return nil
	}
	tf := strings.ToLower(strings.TrimSpace(targetFamily))
	switch tf {
	case "ipv6", "v6", "6":
		for _, ip := range ips {
			if ip.To4() == nil {
				return ip
			}
		}
	case "ipv4", "v4", "4":
		for _, ip := range ips {
			if ip.To4() != nil {
				return ip
			}
		}
	case "follow", "listen":
		lf := strings.ToLower(strings.TrimSpace(listenFamily))
		if lf == "ipv6" {
			for _, ip := range ips {
				if ip.To4() == nil {
					return ip
				}
			}
		} else if lf == "ipv4" {
			for _, ip := range ips {
				if ip.To4() != nil {
					return ip
				}
			}
		}
	}
	// "auto" or unspecified: prefer IPv6 if present (best for IPv6 DDNS), else IPv4
	for _, ip := range ips {
		if ip.To4() == nil {
			return ip
		}
	}
	return ips[0]
}

// ======================= DDNS-aware Target Resolver =======================
//
// Design goals for dynamic (DDNS) IPv6 targets:
//  1. Bypass local DNS caches (systemd-resolved / nscd) by querying public
//     resolvers directly; fall back to the system resolver if all fail.
//  2. Keep the current IP as long as it is still present in the DNS answer
//     (avoids flapping on round-robin records and needless reconnects).
//  3. When the IP really changes, actively close TCP connections / UDP
//     sessions still bound to the stale IP (otherwise they blackhole until
//     keepalive gives up, which takes minutes after an IPv6 prefix change).
//  4. When dialing fails, force an immediate re-resolve and retry once, so
//     the outage window is not bounded by the polling interval.

const (
	ddnsRefreshInterval = 15 * time.Second
	ddnsForceMinGap     = 3 * time.Second
	dnsQueryTimeout     = 2 * time.Second
)

// Public resolvers queried directly (CN + global, v4 + v6). Override via
// env GOFWD_DNS="1.1.1.1:53,[2606:4700:4700::1111]:53".
var dnsServers = func() []string {
	if v := strings.TrimSpace(os.Getenv("GOFWD_DNS")); v != "" {
		var out []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{
		"223.5.5.5:53",
		"119.29.29.29:53",
		"1.1.1.1:53",
		"8.8.8.8:53",
		"[2400:3200::1]:53",
		"[2606:4700:4700::1111]:53",
	}
}()

var directResolvers = func() []*net.Resolver {
	rs := make([]*net.Resolver, 0, len(dnsServers))
	for _, srv := range dnsServers {
		server := srv
		rs = append(rs, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: dnsQueryTimeout}
				return d.DialContext(ctx, network, server)
			},
		})
	}
	return rs
}()

// lookupFresh resolves host bypassing local caches; falls back to system resolver.
// Queries public direct resolvers and local resolver in parallel, taking the fastest response.
func lookupFresh(ctx context.Context, host string) ([]net.IP, error) {
	type res struct {
		ips []net.IP
		err error
	}
	resCh := make(chan res, len(directResolvers)+1)
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	for _, r := range directResolvers {
		go func(resolver *net.Resolver) {
			ips, err := resolver.LookupIP(qctx, "ip", host)
			if err == nil && len(ips) > 0 {
				select {
				case resCh <- res{ips: ips}:
				case <-qctx.Done():
				}
			} else {
				select {
				case resCh <- res{err: err}:
				case <-qctx.Done():
				}
			}
		}(r)
	}

	go func() {
		ips, err := net.DefaultResolver.LookupIP(qctx, "ip", host)
		if err == nil && len(ips) > 0 {
			select {
			case resCh <- res{ips: ips}:
			case <-qctx.Done():
			}
		} else {
			select {
			case resCh <- res{err: err}:
			case <-qctx.Done():
			}
		}
	}()

	total := len(directResolvers) + 1
	var lastErr error
	for i := 0; i < total; i++ {
		select {
		case r := <-resCh:
			if len(r.ips) > 0 {
				return r.ips, nil
			}
			if r.err != nil {
				lastErr = r.err
			}
		case <-qctx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, qctx.Err()
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no IP resolved for %s", host)
}

func containsIP(ips []net.IP, ip net.IP) bool {
	for _, x := range ips {
		if x.Equal(ip) {
			return true
		}
	}
	return false
}

func familyOK(ip net.IP, targetFamily, listenFamily string) bool {
	tf := strings.ToLower(strings.TrimSpace(targetFamily))
	switch tf {
	case "ipv6", "v6", "6":
		return ip.To4() == nil
	case "ipv4", "v4", "4":
		return ip.To4() != nil
	case "follow", "listen":
		lf := strings.ToLower(strings.TrimSpace(listenFamily))
		if lf == "ipv6" {
			return ip.To4() == nil
		} else if lf == "ipv4" {
			return ip.To4() != nil
		}
	}
	return true
}

// trackedConn is an active TCP relay bound to a specific target IP.
type trackedConn struct {
	ip    net.IP
	close func()
}

type TargetResolver struct {
	ctx          context.Context
	remark       string
	targetFamily string
	listenFamily string
	rawTarget    string
	port         int
	isIP         bool
	targetAddr   string
	currIP       atomic.Pointer[net.IP]
	currUDP      atomic.Pointer[net.UDPAddr]

	refreshMu   sync.Mutex // serializes resolves
	lastResolve time.Time

	connMu sync.Mutex
	conns  map[*trackedConn]struct{}

	listenMu  sync.Mutex
	listeners []func(validIPs []net.IP)
}

func newTargetResolver(ctx context.Context, remark, targetFamily, listenFamily, rawTarget string, port int) *TargetResolver {
	tr := &TargetResolver{
		ctx:          ctx,
		remark:       remark,
		targetFamily: targetFamily,
		listenFamily: listenFamily,
		rawTarget:    rawTarget,
		port:         port,
		targetAddr:   net.JoinHostPort(rawTarget, strconv.Itoa(port)),
		conns:        make(map[*trackedConn]struct{}),
	}

	if ip := net.ParseIP(rawTarget); ip != nil {
		tr.isIP = true
		tr.storeIP(ip)
		return tr
	}

	// Initial resolve: wait at most 3s so a DNS outage doesn't stall startup of
	// every rule; until resolved, dials fall back to "host:port" (system resolver).
	done := make(chan error, 1)
	go func() { _, err := tr.resolve(true); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			log.Printf("[WARN][%s] Initial DNS resolve for %s failed: %v (will retry in background)", remark, rawTarget, err)
		}
	case <-time.After(3 * time.Second):
		log.Printf("[WARN][%s] Initial DNS resolve for %s is slow, continuing in background", remark, rawTarget)
	}
	go tr.refreshLoop()
	return tr
}

func (tr *TargetResolver) storeIP(ip net.IP) {
	tr.currIP.Store(&ip)
	tr.currUDP.Store(&net.UDPAddr{IP: ip, Port: tr.port})
}

// CurrentIP returns the cached target IP (nil if never resolved).
func (tr *TargetResolver) CurrentIP() net.IP {
	if p := tr.currIP.Load(); p != nil {
		return *p
	}
	return nil
}

// GetTargetAddr returns "ip:port" of the cached target, or "host:port" if unresolved.
func (tr *TargetResolver) GetTargetAddr() string {
	if ip := tr.CurrentIP(); ip != nil {
		return net.JoinHostPort(ip.String(), strconv.Itoa(tr.port))
	}
	return tr.targetAddr
}

func (tr *TargetResolver) GetUDPAddr() *net.UDPAddr {
	if a := tr.currUDP.Load(); a != nil {
		return a
	}
	if !tr.isIP {
		_, _ = tr.resolve(true)
	}
	return tr.currUDP.Load()
}

// OnChange registers a callback fired (async) when the target IP changes.
// validIPs is the full fresh DNS answer; anything bound to an IP outside it is stale.
func (tr *TargetResolver) OnChange(fn func(validIPs []net.IP)) {
	tr.listenMu.Lock()
	tr.listeners = append(tr.listeners, fn)
	tr.listenMu.Unlock()
}

// resolve performs a fresh lookup. force=false honours ddnsForceMinGap to
// avoid hammering DNS when many dials fail at once. Returns true if IP changed.
func (tr *TargetResolver) resolve(force bool) (bool, error) {
	if tr.isIP {
		return false, nil
	}
	tr.refreshMu.Lock()
	defer tr.refreshMu.Unlock()

	if !force && time.Since(tr.lastResolve) < ddnsForceMinGap {
		return false, nil
	}
	tr.lastResolve = time.Now()

	ctx, cancel := context.WithTimeout(tr.ctx, 8*time.Second)
	ips, err := lookupFresh(ctx, tr.rawTarget)
	cancel()
	if err != nil || len(ips) == 0 {
		return false, err // keep stale IP on failure (serve-stale)
	}

	old := tr.CurrentIP()
	// Sticky: keep current IP if it is still a valid, family-compatible answer.
	if old != nil && containsIP(ips, old) && familyOK(old, tr.targetFamily, tr.listenFamily) {
		return false, nil
	}

	newIP := selectIP(ips, tr.targetFamily, tr.listenFamily)
	if old != nil && newIP.Equal(old) {
		return false, nil
	}
	log.Printf("[DDNS][%s] Target %s IP changed: %v -> %v", tr.remark, tr.rawTarget, old, newIP)
	tr.storeIP(newIP)

	if old != nil {
		tr.closeStale(ips)
		tr.listenMu.Lock()
		ls := append([]func([]net.IP){}, tr.listeners...)
		tr.listenMu.Unlock()
		for _, fn := range ls {
			go fn(ips)
		}
	}
	return true, nil
}

func (tr *TargetResolver) refreshLoop() {
	ticker := time.NewTicker(ddnsRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-tr.ctx.Done():
			return
		case <-ticker.C:
			_, _ = tr.resolve(true)
		}
	}
}

// track registers an active TCP relay; returns an untrack func.
func (tr *TargetResolver) track(ip net.IP, closeFn func()) func() {
	tc := &trackedConn{ip: ip, close: closeFn}
	tr.connMu.Lock()
	tr.conns[tc] = struct{}{}
	tr.connMu.Unlock()
	return func() {
		tr.connMu.Lock()
		delete(tr.conns, tc)
		tr.connMu.Unlock()
	}
}

// closeStale closes TCP relays whose target IP is no longer in the DNS answer.
func (tr *TargetResolver) closeStale(validIPs []net.IP) {
	var stale []*trackedConn
	tr.connMu.Lock()
	for c := range tr.conns {
		if !containsIP(validIPs, c.ip) {
			stale = append(stale, c)
			delete(tr.conns, c)
		}
	}
	tr.connMu.Unlock()
	if len(stale) > 0 {
		log.Printf("[DDNS][%s] Closing %d stale TCP connection(s) bound to old IP", tr.remark, len(stale))
	}
	for _, c := range stale {
		c.close()
	}
}

// udpSession represents a bidirectional UDP forwarding session
type udpSession struct {
	clientAddr net.Addr
	targetIP   net.IP
	targetConn *net.UDPConn
	lastActive atomic.Int64
	closed     atomic.Bool
	closeOnce  sync.Once
}

func (s *udpSession) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.targetConn != nil {
			_ = s.targetConn.Close()
		}
	})
}

// udpRelay manages UDP forwarding for a rule
type udpRelay struct {
	ctx      context.Context
	remark   string
	pc       net.PacketConn
	laddr    *net.UDPAddr
	resolver *TargetResolver
	mu       sync.RWMutex
	sessions map[string]*udpSession
}

func newUDPRelay(ctx context.Context, remark string, pc net.PacketConn, laddr *net.UDPAddr, resolver *TargetResolver) *udpRelay {
	r := &udpRelay{
		ctx:      ctx,
		remark:   remark,
		pc:       pc,
		laddr:    laddr,
		resolver: resolver,
		sessions: make(map[string]*udpSession),
	}
	// On DDNS change, drop sessions bound to the stale IP. Active clients keep
	// refreshing lastActive, so without this they'd never migrate to the new IP.
	resolver.OnChange(r.dropStale)
	return r
}

func (r *udpRelay) dropStale(validIPs []net.IP) {
	var stale []*udpSession
	r.mu.Lock()
	for k, s := range r.sessions {
		if !containsIP(validIPs, s.targetIP) {
			delete(r.sessions, k)
			stale = append(stale, s)
		}
	}
	r.mu.Unlock()
	if len(stale) > 0 {
		log.Printf("[DDNS][%s][UDP] Dropping %d stale session(s) bound to old IP", r.remark, len(stale))
	}
	for _, s := range stale {
		s.Close()
	}
}

func (r *udpRelay) run() {
	go r.cleanupLoop()

	buf := make([]byte, udpBufferSize)
	for {
		n, clientAddr, err := r.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-r.ctx.Done():
				return
			default:
				continue
			}
		}

		key := clientAddr.String()

		// Fast path: check existing session with RLock
		r.mu.RLock()
		sess, ok := r.sessions[key]
		r.mu.RUnlock()

		if !ok || sess.closed.Load() {
			sess = r.createSession(clientAddr, key)
			if sess == nil {
				continue
			}
		}

		sess.lastActive.Store(time.Now().Unix())
		if _, werr := sess.targetConn.Write(buf[:n]); werr != nil && !sess.closed.Load() {
			// e.g. ENETUNREACH after IPv6 prefix change: drop session and re-resolve.
			r.removeSession(key, sess)
			go func() { _, _ = r.resolver.resolve(false) }()
		}
	}
}

func (r *udpRelay) createSession(clientAddr net.Addr, key string) *udpSession {
	targetUDP := r.resolver.GetUDPAddr()
	if targetUDP == nil {
		log.Printf("[WARN][%s][UDP] Cannot resolve target %s for client %s", r.remark, r.resolver.rawTarget, clientAddr)
		return nil
	}

	// Dial target UDP connection with explicit laddr binding if specified (solves GOST #763)
	targetConn, err := net.DialUDP("udp", r.laddr, targetUDP)
	if err != nil {
		// Possibly a stale/unroutable IP after a prefix change: force re-resolve and retry once.
		if changed, _ := r.resolver.resolve(false); changed {
			if t2 := r.resolver.GetUDPAddr(); t2 != nil {
				targetUDP = t2
				targetConn, err = net.DialUDP("udp", r.laddr, targetUDP)
			}
		}
		if err != nil {
			log.Printf("[WARN][%s][UDP] Connect to %s failed: %v", r.remark, targetUDP, err)
			return nil
		}
	}

	sess := &udpSession{
		clientAddr: clientAddr,
		targetIP:   targetUDP.IP,
		targetConn: targetConn,
	}
	sess.lastActive.Store(time.Now().Unix())

	r.mu.Lock()
	// Double check race condition
	if old, exists := r.sessions[key]; exists && !old.closed.Load() {
		r.mu.Unlock()
		_ = targetConn.Close()
		return old
	}

	// Bound capacity to prevent FD exhaustion / UDP flood DoS (solves GOST #363)
	if len(r.sessions) >= maxUDPSessions {
		r.evictOldestLocked()
	}

	r.sessions[key] = sess
	r.mu.Unlock()

	log.Printf("[%s][UDP] SESSION OPEN: %s => %s", r.remark, clientAddr, targetUDP)

	// Launch downstream reader goroutine (Target -> Client)
	go r.readDownstream(sess, key)

	return sess
}

func (r *udpRelay) readDownstream(sess *udpSession, key string) {
	defer func() {
		// Clean up self on exit to prevent zombie sessions (H1)
		r.removeSession(key, sess)
	}()

	buf := make([]byte, udpBufferSize)
	for {
		n, err := sess.targetConn.Read(buf)
		if n > 0 {
			sess.lastActive.Store(time.Now().Unix())
			_, _ = r.pc.WriteTo(buf[:n], sess.clientAddr)
		}
		if err != nil {
			return
		}
	}
}

func (r *udpRelay) removeSession(key string, sess *udpSession) {
	sess.Close()

	r.mu.Lock()
	if cur, ok := r.sessions[key]; ok && cur == sess {
		delete(r.sessions, key)
	}
	r.mu.Unlock()
}

func (r *udpRelay) evictOldestLocked() {
	var oldestKey string
	var oldestTime int64 = 1<<62 - 1
	var oldestSess *udpSession

	for k, s := range r.sessions {
		act := s.lastActive.Load()
		if act < oldestTime {
			oldestTime = act
			oldestKey = k
			oldestSess = s
		}
	}

	if oldestSess != nil {
		delete(r.sessions, oldestKey)
		go oldestSess.Close()
	}
}

func (r *udpRelay) cleanupLoop() {
	ticker := time.NewTicker(udpCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			r.mu.Lock()
			toClose := make([]*udpSession, 0, len(r.sessions))
			for _, s := range r.sessions {
				toClose = append(toClose, s)
			}
			r.sessions = make(map[string]*udpSession)
			r.mu.Unlock()

			for _, s := range toClose {
				s.Close()
			}
			return

		case <-ticker.C:
			now := time.Now().Unix()
			var toClose []*udpSession

			r.mu.Lock()
			for k, s := range r.sessions {
				if now-s.lastActive.Load() > int64(udpSessionTimeout.Seconds()) || s.closed.Load() {
					delete(r.sessions, k)
					toClose = append(toClose, s)
				}
			}
			r.mu.Unlock()

			for _, s := range toClose {
				s.Close()
			}
		}
	}
}

// TCP Relay with Linux splice zero-copy & proper half-close support (H5, GOST #6d67be8)
func handleTCPConnection(ctx context.Context, id uint64, remark string, client *net.TCPConn, tr *TargetResolver, dialer *net.Dialer) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()
	startTime := time.Now()

	// Dial the currently cached target IP; on failure force a fresh DNS lookup
	// and retry once if the IP changed (shrinks the DDNS outage window).
	targetAddr := tr.GetTargetAddr()
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil && !tr.isIP {
		if changed, _ := tr.resolve(false); changed {
			retryAddr := tr.GetTargetAddr()
			log.Printf("[#%d][%s] Dial %s failed (%v), retrying with refreshed target %s", id, remark, targetAddr, err, retryAddr)
			targetAddr = retryAddr
			conn, err = dialer.DialContext(ctx, "tcp", targetAddr)
		}
	}
	if err != nil {
		log.Printf("[#%d][%s] Connect to target %s failed: %v (client: %s)", id, remark, targetAddr, err, clientAddr)
		return
	}
	defer conn.Close()

	target, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}

	// Register so a DDNS change can tear this relay down if its IP goes stale.
	var dialedIP net.IP
	if ra, ok := target.RemoteAddr().(*net.TCPAddr); ok {
		dialedIP = ra.IP
	}
	if dialedIP != nil && !tr.isIP {
		untrack := tr.track(dialedIP, func() {
			_ = client.Close()
			_ = target.Close()
		})
		defer untrack()
	}

	_ = client.SetNoDelay(true)
	_ = target.SetNoDelay(true)
	_ = client.SetKeepAlive(true)
	_ = client.SetKeepAlivePeriod(30 * time.Second)
	_ = target.SetKeepAlive(true)
	_ = target.SetKeepAlivePeriod(15 * time.Second)

	remoteTargetAddr := target.RemoteAddr().String()
	log.Printf("[#%d][%s][TCP] ESTABLISHED: %s => %s (target IP: %s)", id, remark, clientAddr, targetAddr, remoteTargetAddr)

	var upBytes, downBytes atomic.Int64
	errc := make(chan error, 2)

	// Client -> Target (Upload)
	go func() {
		n, copyErr := io.Copy(target, client)
		upBytes.Store(n)
		_ = target.CloseWrite()
		errc <- copyErr
	}()

	// Target -> Client (Download)
	go func() {
		n, copyErr := io.Copy(client, target)
		downBytes.Store(n)
		_ = client.CloseWrite()
		errc <- copyErr
	}()

	// Wait for the first direction to finish
	firstErr := <-errc

	if firstErr != nil && !isNormalClose(firstErr) {
		// Connection aborted or read error, terminate both ends immediately
		_ = client.Close()
		_ = target.Close()
		<-errc
	} else {
		// Normal half-close: set deadline on remaining direction
		dl := time.Now().Add(tcpHalfCloseTimeout)
		_ = client.SetDeadline(dl)
		_ = target.SetDeadline(dl)

		_ = <-errc
		_ = client.Close()
		_ = target.Close()
	}

	duration := time.Since(startTime).Round(time.Millisecond)
	up := upBytes.Load()
	down := downBytes.Load()
	log.Printf("[#%d][%s][TCP] CLOSED: %s => %s | Up: %d bytes, Down: %d bytes, Duration: %v", id, remark, clientAddr, targetAddr, up, down, duration)
}

func isNormalClose(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}

func main() {
	configPath := "/etc/go-forwarder/rules.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	} else if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if _, err := os.Stat("/etc/realm/rules.json"); err == nil {
			configPath = "/etc/realm/rules.json"
		}
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read rules file %s: %v", configPath, err)
	}

	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	var activeListeners []io.Closer

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Validation (L1)
		if rule.ListenPort < 1 || rule.ListenPort > 65535 {
			log.Printf("[WARN][%s] Invalid listen port %d, skipping rule", rule.Remark, rule.ListenPort)
			continue
		}
		if rule.TargetPort < 1 || rule.TargetPort > 65535 {
			log.Printf("[WARN][%s] Invalid target port %d, skipping rule", rule.Remark, rule.TargetPort)
			continue
		}
		targetHost := strings.TrimSpace(rule.Target)
		if targetHost == "" {
			log.Printf("[WARN][%s] Target is empty, skipping rule", rule.Remark)
			continue
		}

		// Protocol parsing (H6)
		proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
		enableTCP := false
		enableUDP := false
		switch proto {
		case "tcp":
			enableTCP = true
		case "udp":
			enableUDP = true
		case "", "both", "all", "tcp+udp", "tcp/udp", "udp+tcp":
			enableTCP = true
			enableUDP = true
		default:
			log.Printf("[WARN][%s] Unknown protocol %q, defaulting to TCP+UDP", rule.Remark, rule.Protocol)
			enableTCP = true
			enableUDP = true
		}

		// Bind address & network parsing (H6, M5, GOST #763)
		listenIP := strings.TrimSpace(rule.ListenIP)
		listenAddr := net.JoinHostPort(listenIP, strconv.Itoa(rule.ListenPort))
		tcpNetwork := "tcp"
		udpNetwork := "udp"

		if rule.ListenFamily == "ipv4" {
			tcpNetwork = "tcp4"
			udpNetwork = "udp4"
			if listenIP == "" {
				listenAddr = fmt.Sprintf("0.0.0.0:%d", rule.ListenPort)
			}
		} else if rule.ListenFamily == "ipv6" {
			tcpNetwork = "tcp6"
			udpNetwork = "udp6"
			if listenIP == "" {
				listenAddr = fmt.Sprintf("[::]:%d", rule.ListenPort)
			}
		} else {
			if listenIP == "" {
				listenAddr = fmt.Sprintf(":%d", rule.ListenPort)
			}
		}

		// TargetResolver with DDNS & Family matching
		targetResolver := newTargetResolver(ctx, rule.Remark, rule.TargetFamily, rule.ListenFamily, targetHost, rule.TargetPort)

		// Rule-specific Dialer binding local IP if specified (solves GOST #763 for multi-IP hosts)
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		var udpLAddr *net.UDPAddr

		// 1. TCP Listener
		if enableTCP {
			tcpLn, err := net.Listen(tcpNetwork, listenAddr)
			if err != nil {
				log.Printf("[ERROR] TCP listen error on %s %s (%s): %v", tcpNetwork, listenAddr, rule.Remark, err)
			} else {
				log.Printf("[INIT] Listening TCP on %s %s -> %s (%s)", tcpNetwork, listenAddr, targetResolver.targetAddr, rule.Remark)
				activeListeners = append(activeListeners, tcpLn)
				wg.Add(1)
				go func(r Rule, l net.Listener, tr *TargetResolver, d *net.Dialer) {
					defer wg.Done()
					defer l.Close()

					var delay time.Duration
					for {
						clientConn, err := l.Accept()
						if err != nil {
							if errors.Is(err, net.ErrClosed) {
								return
							}
							// Exponential backoff on temporary accept errors (H4, GOST #914)
							if delay == 0 {
								delay = 5 * time.Millisecond
							} else {
								delay *= 2
							}
							if maxDelay := 1 * time.Second; delay > maxDelay {
								delay = maxDelay
							}
							log.Printf("[WARN][%s] Accept error: %v, retry in %v", r.Remark, err, delay)
							select {
							case <-time.After(delay):
								continue
							case <-ctx.Done():
								return
							}
						}
						delay = 0

						tc, ok := clientConn.(*net.TCPConn)
						if !ok {
							_ = clientConn.Close()
							continue
						}

						// Concurrency limiter check (M1, GOST #49c998e)
						select {
						case tcpSem <- struct{}{}:
						default:
							log.Printf("[WARN][%s] Max concurrent TCP connections reached, dropping new connection from %s", r.Remark, tc.RemoteAddr())
							_ = tc.Close()
							continue
						}

						id := connID.Add(1)
						wg.Add(1)
						go func(cid uint64, c *net.TCPConn) {
							defer func() {
								<-tcpSem
								wg.Done()
							}()
							handleTCPConnection(ctx, cid, r.Remark, c, tr, d)
						}(id, tc)
					}
				}(rule, tcpLn, targetResolver, dialer)
			}
		}

		// 2. UDP Listener
		if enableUDP {
			udpConn, err := net.ListenPacket(udpNetwork, listenAddr)
			if err != nil {
				log.Printf("[ERROR] UDP listen error on %s %s (%s): %v", udpNetwork, listenAddr, rule.Remark, err)
			} else {
				log.Printf("[INIT] Listening UDP on %s %s -> %s (%s)", udpNetwork, listenAddr, targetResolver.targetAddr, rule.Remark)
				activeListeners = append(activeListeners, udpConn)
				wg.Add(1)
				go func(r Rule, pc net.PacketConn, laddr *net.UDPAddr, tr *TargetResolver) {
					defer wg.Done()
					defer pc.Close()
					relay := newUDPRelay(ctx, r.Remark, pc, laddr, tr)
					relay.run()
				}(rule, udpConn, udpLAddr, targetResolver)
			}
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("Received signal %v, shutting down listeners...", sig)
	cancel()

	for _, l := range activeListeners {
		_ = l.Close()
	}

	// Wait up to 5s for active connections to finish cleanly (M4)
	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
		log.Println("All connections closed. Graceful shutdown complete.")
	case <-time.After(5 * time.Second):
		log.Println("Timed out waiting for active connections to finish. Forcing exit.")
	}
}
