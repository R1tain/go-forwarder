package main

import (
	"context"
	"net"
	"testing"
	"time"
)

// Verifies sticky selection, stale-conn teardown and OnChange notification
// without real network I/O, by driving resolve() through /etc/hosts-free
// IP targets is impossible; so we exercise the internal state machine directly.
func TestCloseStaleAndSticky(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := &TargetResolver{ctx: ctx, remark: "t", family: "ipv6", rawTarget: "x", port: 1,
		conns: make(map[*trackedConn]struct{})}

	oldIP := net.ParseIP("2404:c805:5a03:5301::5f9")
	newIP := net.ParseIP("2404:c805:5a03:9999::5f9")
	tr.storeIP(oldIP)

	closedOld, closedNew := false, false
	u1 := tr.track(oldIP, func() { closedOld = true })
	u2 := tr.track(newIP, func() { closedNew = true })
	defer u1()
	defer u2()

	tr.closeStale([]net.IP{newIP})
	if !closedOld || closedNew {
		t.Fatalf("closeStale wrong: old=%v new=%v", closedOld, closedNew)
	}
	if len(tr.conns) != 1 {
		t.Fatalf("expected 1 tracked conn left, got %d", len(tr.conns))
	}

	// familyOK / selectIP behaviour for ipv6 rules
	v4 := net.ParseIP("1.2.3.4")
	if familyOK(v4, "ipv6") || !familyOK(newIP, "ipv6") || !familyOK(v4, "dual") {
		t.Fatal("familyOK wrong")
	}
	if got := selectIP([]net.IP{v4, newIP}, "ipv6"); !got.Equal(newIP) {
		t.Fatalf("selectIP ipv6 picked %v", got)
	}
	if got := tr.GetTargetAddr(); got != "[2404:c805:5a03:5301::5f9]:1" {
		t.Fatalf("GetTargetAddr=%s", got)
	}
}

func TestUDPDropStale(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := &TargetResolver{ctx: ctx, conns: make(map[*trackedConn]struct{})}
	r := newUDPRelay(ctx, "t", nil, nil, tr)
	oldIP, newIP := net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	r.sessions["a"] = &udpSession{targetIP: oldIP}
	r.sessions["b"] = &udpSession{targetIP: newIP}
	r.dropStale([]net.IP{newIP})
	if _, ok := r.sessions["a"]; ok {
		t.Fatal("stale UDP session not dropped")
	}
	if _, ok := r.sessions["b"]; !ok {
		t.Fatal("valid UDP session wrongly dropped")
	}
	if len(tr.listeners) != 1 {
		t.Fatal("udp relay did not register OnChange")
	}
	_ = time.Second
}
