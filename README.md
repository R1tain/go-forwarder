# go-forwarder

High-performance Layer-4 TCP/UDP port forwarder written in Go, featuring Linux kernel `splice(2)` zero-copy, RFC-compliant TCP half-close handling, and resilient UDP session management with DDNS auto-refresh.

---

## 🌟 Features

- **🚀 Linux Kernel `splice(2)` Zero-Copy**:
  Utilizes kernel-space pipe-based zero-copy data transfer for TCP connections, eliminating user-space memory buffers and context switches.
- **🔄 Robust TCP Half-Close (`SHUT_WR`)**:
  Properly propagates `CloseWrite` (TCP FIN) when one direction finishes, allowing the reverse direction to complete its transmission without truncating responses or triggering TCP RST.
- **🛡️ Resilient UDP Session Management**:
  - Non-blocking UDP socket dialing (<5µs, zero DNS lock contention).
  - Self-healing from ICMP Port Unreachable errors (no zombie sessions when backends restart).
  - Maximum session cap (`maxUDPSessions = 4096`) with LRU eviction to prevent FD exhaustion and DoS.
  - Zero lock contention on the UDP hot path.
- **🌐 Dynamic DDNS Auto-Refresh**:
  Background periodic DNS resolver (every 30s) with serve-stale resilience (keeps old IP if DNS queries fail temporarily).
- **⚙️ Fault-Tolerant Listener Loops**:
  Exponential backoff (5ms up to 1s) upon temporary accept errors (e.g. `EMFILE`), preventing listener threads from prematurely exiting.
- **🛑 Graceful Shutdown**:
  Listens for `SIGINT` / `SIGTERM`, safely closes listeners to unblock worker routines, and waits up to 5s for active transfers to drain.

---

## 📋 Configuration (`rules.json`)

```json
[
  {
    "id": 1,
    "remark": "ss2022-hkt",
    "listen_family": "ipv6",
    "listen_ip": "",
    "listen_port": 56977,
    "protocol": "both",
    "target": "v6.tamanet.yester-day.de",
    "target_port": 56977,
    "enabled": true
  },
  {
    "id": 2,
    "remark": "ipv4-tcp-only",
    "listen_family": "ipv4",
    "listen_ip": "127.0.0.1",
    "listen_port": 8080,
    "protocol": "tcp",
    "target": "1.1.1.1",
    "target_port": 8080,
    "enabled": true
  }
]
```

### Protocol Options
- `"tcp"`: Forward TCP traffic only.
- `"udp"`: Forward UDP traffic only.
- `"both"` / `"all"` / `"tcp+udp"`: Forward both TCP and UDP.

---

## 🔨 Build & Installation

### Local Build
```bash
go build -ldflags="-s -w" -o go-forwarder main.go
```

### Cross-Compilation for Linux AMD64
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o go-forwarder main.go
```

### Systemd Deployment
1. Copy the binary:
   ```bash
   cp go-forwarder /usr/local/bin/go-forwarder
   chmod +x /usr/local/bin/go-forwarder
   ```
2. Install systemd service:
   ```bash
   cp go-forwarder.service /etc/systemd/system/go-forwarder.service
   systemctl daemon-reload
   systemctl enable --now go-forwarder
   ```
3. Check service status:
   ```bash
   systemctl status go-forwarder
   journalctl -u go-forwarder -f
   ```

---

## 📄 License
MIT License.
