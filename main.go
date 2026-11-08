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
	Enabled      bool   `json:"enabled"`
	Created      string `json:"created,omitempty"`
}

const (
	maxUDPSessions     = 4096
	udpSessionTimeout  = 60 * time.Second
	udpCleanupInterval = 10 * time.Second
	udpBufferSize      = 65535
	tcpHalfCloseTimeout= 30 * time.Second
	maxTCPConnections  = 10000
)

var (
	connID  atomic.Uint64
	tcpSem  = make(chan struct{}, maxTCPConnections)
)

// TargetResolver resolves and caches target IP/UDPAddr with periodic DDNS refresh
type TargetResolver struct {
	remark     string
	rawTarget  string
	port       int
	isIP       bool
	targetAddr string
	currIP     atomic.Pointer[net.IP]
	currUDP    atomic.Pointer[net.UDPAddr]
}

func newTargetResolver(ctx context.Context, remark, rawTarget string, port int) *TargetResolver {
	tr := &TargetResolver{
		remark:     remark,
		rawTarget:  rawTarget,
		port:       port,
		targetAddr: net.JoinHostPort(rawTarget, strconv.Itoa(port)),
	}

	if ip := net.ParseIP(rawTarget); ip != nil {
		tr.isIP = true
		tr.currIP.Store(&ip)
		tr.currUDP.Store(&net.UDPAddr{IP: ip, Port: port})
		return tr
	}

	// Hostname: initial resolve
	resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", rawTarget)
	cancel()
	if err == nil && len(ips) > 0 {
		chosenIP := ips[0]
		tr.currIP.Store(&chosenIP)
		tr.currUDP.Store(&net.UDPAddr{IP: chosenIP, Port: port})
	} else {
		log.Printf("[WARN][%s] Initial DNS resolve for %s failed: %v (will retry in background)", remark, rawTarget, err)
	}

	go tr.refreshLoop(ctx)
	return tr
}

func (tr *TargetResolver) GetUDPAddr() *net.UDPAddr {
	addr := tr.currUDP.Load()
	if addr != nil {
		return addr
	}

	// Fallback synchronous resolve if not cached yet
	if tr.isIP {
		if ip := net.ParseIP(tr.rawTarget); ip != nil {
			a := &net.UDPAddr{IP: ip, Port: tr.port}
			tr.currUDP.Store(a)
			return a
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", tr.rawTarget)
	if err == nil && len(ips) > 0 {
		chosen := ips[0]
		tr.currIP.Store(&chosen)
		a := &net.UDPAddr{IP: chosen, Port: tr.port}
		tr.currUDP.Store(a)
		return a
	}
	return nil
}

func (tr *TargetResolver) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", tr.rawTarget)
			cancel()
			if err != nil || len(ips) == 0 {
				// Keep stale IP on failure
				continue
			}
			newIP := ips[0]
			oldIP := tr.currIP.Load()
			if oldIP == nil || !newIP.Equal(*oldIP) {
				log.Printf("[DDNS][%s] Target %s IP changed: %v -> %v", tr.remark, tr.rawTarget, oldIP, newIP)
				tr.currIP.Store(&newIP)
				tr.currUDP.Store(&net.UDPAddr{IP: newIP, Port: tr.port})
			}
		}
	}
}

// udpSession represents a bidirectional UDP forwarding session
type udpSession struct {
	clientAddr net.Addr
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
	resolver *TargetResolver
	mu       sync.RWMutex
	sessions map[string]*udpSession
}

func newUDPRelay(ctx context.Context, remark string, pc net.PacketConn, resolver *TargetResolver) *udpRelay {
	return &udpRelay{
		ctx:      ctx,
		remark:   remark,
		pc:       pc,
		resolver: resolver,
		sessions: make(map[string]*udpSession),
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

		// Fast path: existing session
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
		_, _ = sess.targetConn.Write(buf[:n])
	}
}

func (r *udpRelay) createSession(clientAddr net.Addr, key string) *udpSession {
	targetUDP := r.resolver.GetUDPAddr()
	if targetUDP == nil {
		log.Printf("[WARN][%s][UDP] Cannot resolve target %s for client %s", r.remark, r.resolver.rawTarget, clientAddr)
		return nil
	}

	// Dial target UDP connection without holding the mutex
	targetConn, err := net.DialUDP("udp", nil, targetUDP)
	if err != nil {
		log.Printf("[WARN][%s][UDP] Connect to %s failed: %v", r.remark, targetUDP, err)
		return nil
	}

	sess := &udpSession{
		clientAddr: clientAddr,
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

	// Bound capacity to prevent FD exhaustion / UDP flood DoS
	if len(r.sessions) >= maxUDPSessions {
		r.evictOldestLocked()
	}

	r.sessions[key] = sess
	r.mu.Unlock()

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

// TCP Relay with Linux splice zero-copy & proper half-close support (H5)
func handleTCPConnection(ctx context.Context, id uint64, remark string, client *net.TCPConn, targetAddr string, dialer *net.Dialer) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()
	startTime := time.Now()

	// Dial target with context
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		log.Printf("[#%d][%s] Connect to target %s failed: %v (client: %s)", id, remark, targetAddr, err, clientAddr)
		return
	}
	defer conn.Close()

	target, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}

	_ = client.SetNoDelay(true)
	_ = target.SetNoDelay(true)
	_ = client.SetKeepAlive(true)
	_ = client.SetKeepAlivePeriod(30 * time.Second)
	_ = target.SetKeepAlive(true)
	_ = target.SetKeepAlivePeriod(30 * time.Second)

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
	configPath := "/etc/realm/rules.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
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

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

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

		// Bind address & network parsing (H6, M5)
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

		targetResolver := newTargetResolver(ctx, rule.Remark, targetHost, rule.TargetPort)

		// 1. TCP Listener
		if enableTCP {
			tcpLn, err := net.Listen(tcpNetwork, listenAddr)
			if err != nil {
				log.Printf("[ERROR] TCP listen error on %s %s (%s): %v", tcpNetwork, listenAddr, rule.Remark, err)
			} else {
				log.Printf("[INIT] Listening TCP on %s %s -> %s (%s)", tcpNetwork, listenAddr, targetResolver.targetAddr, rule.Remark)
				activeListeners = append(activeListeners, tcpLn)
				wg.Add(1)
				go func(r Rule, l net.Listener, target string) {
					defer wg.Done()
					defer l.Close()

					var delay time.Duration
					for {
						clientConn, err := l.Accept()
						if err != nil {
							if errors.Is(err, net.ErrClosed) {
								return
							}
							// Exponential backoff on temporary accept errors (H4)
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

						// Concurrency limiter check (M1)
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
							handleTCPConnection(ctx, cid, r.Remark, c, target, dialer)
						}(id, tc)
					}
				}(rule, tcpLn, targetResolver.targetAddr)
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
				go func(r Rule, pc net.PacketConn, tr *TargetResolver) {
					defer wg.Done()
					defer pc.Close()
					relay := newUDPRelay(ctx, r.Remark, pc, tr)
					relay.run()
				}(rule, udpConn, targetResolver)
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
