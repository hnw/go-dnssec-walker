package main

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"strconv"
)

func main() {
	var (
		qtype  []uint16
		qclass []uint16
		qname  []string
	)

	aa := flag.Bool("aa", false, "set AA flag in query")
	ad := flag.Bool("ad", false, "set AD flag in query")
	cd := flag.Bool("cd", false, "set CD flag in query")
	rd := flag.Bool("rd", true, "set RD flag in query")

	query := flag.Bool("question", false, "show question")
	port := flag.Int("port", 53, "port number to use")
	fallback := flag.Bool("fallback", false, "fallback to 4096 bytes bufsize and after that TCP")

	//qname = append(qname, "biz.")
	//qtype = append(qtype, dns.TypeNSEC)
	qname = append(qname, "-.biz")
	qtype = append(qtype, dns.TypeA)
	qclass = append(qclass, dns.ClassINET)

	var nameserver string

	{
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		nameserver = "@" + conf.Servers[0]
	}

	nameserver = string([]byte(nameserver)[1:]) // chop off @
	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name
	if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
		nameserver = nameserver[1 : len(nameserver)-1]
	}
	if i := net.ParseIP(nameserver); i != nil {
		nameserver = net.JoinHostPort(nameserver, strconv.Itoa(*port))
	} else {
		nameserver = dns.Fqdn(nameserver) + ":" + strconv.Itoa(*port)
	}

	c := new(dns.Client)
	t := new(dns.Transfer)
	c.Net = "udp"

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = *aa
	m.MsgHdr.AuthenticatedData = *ad
	m.MsgHdr.CheckingDisabled = *cd
	m.MsgHdr.RecursionDesired = *rd
	m.Question = make([]dns.Question, 1)
	m.Opcode = dns.OpcodeQuery
	m.Rcode = dns.RcodeSuccess

	{
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetDo()
		o.SetUDPSize(dns.DefaultMsgSize)
		m.Extra = append(m.Extra, o)
	}
	qt := dns.TypeA
	qc := uint16(dns.ClassINET)

Query:
	for i, v := range qname {
		if i < len(qtype) {
			qt = qtype[i]
		}
		if i < len(qclass) {
			qc = qclass[i]
		}
		m.Question[0] = dns.Question{dns.Fqdn(v), qt, qc}
		m.Id = dns.Id()
		if *query {
			fmt.Printf("%s", m.String())
			fmt.Printf("\n;; size: %d bytes\n\n", m.Len())
		}
		if qt == dns.TypeAXFR || qt == dns.TypeIXFR {
			env, err := t.In(m, nameserver)
			if err != nil {
				fmt.Printf(";; %s\n", err.Error())
				continue
			}
			envelope := 0
			record := 0
			for e := range env {
				if e.Error != nil {
					fmt.Printf(";; %s\n", e.Error.Error())
					continue Query
				}
				for _, r := range e.RR {
					fmt.Printf("%s\n", r)
				}
				record += len(e.RR)
				envelope++
			}
			fmt.Printf("\n;; xfr size: %d records (envelopes %d)\n", record, envelope)
			continue
		}
		r, _ /*rtt*/, e := c.Exchange(m, nameserver)
	Redo:
		if e != nil {
			fmt.Printf(";; %s\n", e.Error())
			continue
		}

		if r.Id != m.Id {
			fmt.Fprintf(os.Stderr, "Id mismatch\n")
			return
		}

		if r.MsgHdr.Truncated && *fallback {
			// First EDNS, then TCP
			fmt.Printf(";; Truncated, trying TCP\n")
			c.Net = "tcp"
			r, _ /*rtt*/, e = c.Exchange(m, nameserver)
			goto Redo
		}

		if r.MsgHdr.Truncated && !*fallback {
			fmt.Printf(";; Truncated\n")
		}

		nextDomain(r)

		fmt.Printf("%v", r)
		//fmt.Printf("\n;; query time: %.3d µs, server: %s(%s), size: %d bytes\n", rtt/1e3, nameserver, c.Net, r.Len())
	}
}

func nextDomain(in *dns.Msg) {
	denial := make([]dns.RR, 0)
	// nsec(3) live in the auth section
	nsec := false
	nsec3 := false
	fmt.Fprintln(os.Stderr, in.Answer)
	fmt.Fprintln(os.Stderr, in.Ns)
	for _, rr := range in.Ns {
		fmt.Fprintln(os.Stderr, "--=====")
		if rr.Header().Rrtype == dns.TypeNSEC {
			fmt.Fprintln(os.Stderr, rr.Header().Name)
			fmt.Fprintln(os.Stderr, rr.(*dns.NSEC).NextDomain)
			//fmt.Fprintln(os.Stderr, rr.(*dns.NSEC).TypeBitMap)

			denial = append(denial, rr)
			nsec = true
			continue
		}
		if rr.Header().Rrtype == dns.TypeNSEC3 {
			fmt.Fprintln(os.Stderr, "nsec3")

			denial = append(denial, rr)
			nsec3 = true
			continue
		}
	}
	if nsec && nsec3 {
		// What??! Both NSEC and NSEC3 in there?
		return
	}
	if nsec3 {
		return
	}
	if nsec {
		return
	}
}
