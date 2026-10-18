// SPDX-License-Identifier: MPL-2.0

package acmetest

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// DNS is an authoritative name server for test zones. It answers SOA, NS and
// TXT queries, and accepts RFC 2136 updates to TXT records signed with the
// TSIG key it was started with.
type DNS struct {
	// Addr is host:port, on both UDP and TCP.
	Addr string

	zones []string

	mu  sync.Mutex
	txt map[string][]string
}

// TSIG is a key the server accepts for updates.
type TSIG struct {
	Name, Secret string
}

// StartDNS serves zones until the test ends. Without a key, updates are
// refused.
func StartDNS(t testing.TB, key *TSIG, zones ...string) *DNS {
	t.Helper()
	d := &DNS{txt: map[string][]string{}}
	for _, z := range zones {
		d.zones = append(d.zones, dns.Fqdn(strings.ToLower(z)))
	}

	var secrets map[string]string
	if key != nil {
		secrets = map[string]string{dns.Fqdn(key.Name): key.Secret}
	}

	var udp net.PacketConn
	var tcp net.Listener
	for range 10 {
		var err error
		if udp, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if tcp, err = net.Listen("tcp", udp.LocalAddr().String()); err == nil {
			break
		}
		udp.Close()
		udp = nil
	}
	if udp == nil {
		t.Fatal("no free port for UDP and TCP")
	}
	d.Addr = udp.LocalAddr().String()

	handler := dns.HandlerFunc(d.serve)
	// The default accept function answers UPDATE with NOTIMP.
	accept := func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }
	servers := []*dns.Server{
		{PacketConn: udp, Handler: handler, TsigSecret: secrets, MsgAcceptFunc: accept},
		{Listener: tcp, Handler: handler, TsigSecret: secrets, MsgAcceptFunc: accept},
	}
	for _, s := range servers {
		go func() { _ = s.ActivateAndServe() }()
	}
	t.Cleanup(func() {
		for _, s := range servers {
			_ = s.Shutdown()
		}
	})
	return d
}

// TXT returns the TXT values published for name.
func (d *DNS) TXT(name string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.txt[dns.Fqdn(strings.ToLower(name))]...)
}

// SetTXT adds a TXT value, as a provider's API would.
func (d *DNS) SetTXT(name, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := dns.Fqdn(strings.ToLower(name))
	d.txt[k] = append(d.txt[k], value)
}

// DeleteTXT removes a TXT value.
func (d *DNS) DeleteTXT(name, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	k := dns.Fqdn(strings.ToLower(name))
	var kept []string
	for _, v := range d.txt[k] {
		if v != value {
			kept = append(kept, v)
		}
	}
	if len(kept) == 0 {
		delete(d.txt, k)
	} else {
		d.txt[k] = kept
	}
}

func (d *DNS) zoneOf(name string) string {
	name = strings.ToLower(name)
	for _, z := range d.zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			return z
		}
	}
	return ""
}

func (d *DNS) soa(zone string) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "ns." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 60, Retry: 60, Expire: 600, Minttl: 60,
	}
}

func (d *DNS) serve(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if r.Opcode == dns.OpcodeUpdate {
		m.Rcode = d.update(w, r)
	} else if len(r.Question) == 1 {
		d.answer(m, r.Question[0])
	} else {
		m.Rcode = dns.RcodeFormatError
	}

	if t := r.IsTsig(); t != nil && w.TsigStatus() == nil {
		m.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
	}
	_ = w.WriteMsg(m)
}

func (d *DNS) answer(m *dns.Msg, q dns.Question) {
	name := strings.ToLower(q.Name)
	zone := d.zoneOf(name)
	if zone == "" {
		m.Rcode = dns.RcodeRefused
		m.Authoritative = false
		return
	}
	hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
	switch {
	case q.Qtype == dns.TypeSOA && name == zone:
		m.Answer = append(m.Answer, d.soa(zone))
	case q.Qtype == dns.TypeNS && name == zone:
		m.Answer = append(m.Answer, &dns.NS{Hdr: hdr, Ns: "ns." + zone})
	case q.Qtype == dns.TypeA && name == "ns."+zone:
		m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1)})
	case q.Qtype == dns.TypeTXT:
		for _, v := range d.TXT(name) {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{v}})
		}
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, d.soa(zone))
	}
}

func (d *DNS) update(w dns.ResponseWriter, r *dns.Msg) int {
	if r.IsTsig() == nil || w.TsigStatus() != nil {
		return dns.RcodeRefused
	}
	if len(r.Question) != 1 || d.zoneOf(r.Question[0].Name) != strings.ToLower(r.Question[0].Name) {
		return dns.RcodeNotZone
	}
	for _, rr := range r.Ns {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		value := strings.Join(txt.Txt, "")
		switch txt.Hdr.Class {
		case dns.ClassINET:
			d.SetTXT(txt.Hdr.Name, value)
		case dns.ClassNONE:
			d.DeleteTXT(txt.Hdr.Name, value)
		}
	}
	return dns.RcodeSuccess
}
