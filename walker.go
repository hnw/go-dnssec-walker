package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var debug *bool

func main() {
	debug = flag.Bool("debug", false, "enable debugging in the resolver")
	port := flag.Int("port", 53, "port number to use")
	startfrom := flag.String("startfrom", "0", "start the zone walk at")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [@nameserver] zone\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var nameserver, zone string

Flags:
	for i := 0; i < flag.NArg(); i++ {
		// If it starts with @ it is a nameserver
		if flag.Arg(i)[0] == '@' {
			nameserver = flag.Arg(i)
			continue Flags
		}
		zone = flag.Arg(i)
		break
	}

	if len(nameserver) == 0 {
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

	re, _ := regexp.Compile(`\.*$`)
	zone = re.ReplaceAllString(zone, ".")

	//r, _, _ := dnssecQuery(nameserver, "biz", dns.TypeNSEC)

	prev := ``
	next := *startfrom

	for {
		prev, next, _ = searchNsecGap(nameserver, next, zone)
		if prev != `` {
			fmt.Printf("%s.%s\n", prev, zone)
		}
		if next == `` {
			break
		}
	}

	//fmt.Printf("%v", r)
	//fmt.Printf("\n;; query time: %.3d us, server: %s(%s), size: %d bytes\n", rtt/1e3, nameserver, c.Net, r.Len())
}

func searchNsecGap(a string, label string, zone string) (prev string, next string, err error) {
	gap := strings.ToLower(label) + `-`
	if len(gap) > 63 {
		c := gap[62]

		if c == '-' {
			gap = gap[0:62] + `0`
		} else if c == '9' {
			gap = gap[0:62] + `a`
		} else {
			// TODO:63文字目がzの場合に多分死ぬ
			gap = gap[0:62] + string(c+1)
		}
	}

	qn := gap + `.` + zone
	qt := dns.TypeA

	re, _ := regexp.Compile(`^(([^\.]+\.)*([^\.]+)\.|)` + zone + `\.*$`)

	retry := 0
Redo:
	in, _, err := dnssecQuery(a, qn, qt)

	if err != nil {
		if retry < 3 {
			retry++
			goto Redo
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	for _, rr := range in.Answer {
		if rr.Header().Rrtype == dns.TypeA {
			return rr.Header().Name, rr.(*dns.NSEC).NextDomain, nil
		}
	}
	for _, rr := range in.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC {
			prev := strings.ToLower(rr.Header().Name)
			next := strings.ToLower(rr.(*dns.NSEC).NextDomain)

			if !re.MatchString(prev) || !re.MatchString(next) {
				continue
			}
			prev = re.ReplaceAllString(prev, "${3}")
			next = re.ReplaceAllString(next, "${3}")

			if prev < gap && (gap < next || next == ``) {
				return prev, next, nil
			}
		}
	}
	fmt.Fprintf(os.Stderr, "no next domain\n%v", in)
	os.Exit(2)
	return
}

func dnssecQuery(a string, qn string, qt uint16) (r *dns.Msg, rtt time.Duration, err error) {

	c := new(dns.Client)
	c.Net = "udp"

	m := new(dns.Msg)
	m.MsgHdr.Authoritative = false
	m.MsgHdr.AuthenticatedData = false
	m.MsgHdr.CheckingDisabled = false
	m.MsgHdr.RecursionDesired = true
	m.Question = make([]dns.Question, 1)
	m.Opcode = dns.OpcodeQuery
	m.Rcode = dns.RcodeSuccess

	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	o.SetUDPSize(dns.DefaultMsgSize)
	m.Extra = append(m.Extra, o)

	qc := uint16(dns.ClassINET)

	m.Question[0] = dns.Question{dns.Fqdn(qn), qt, qc}
	m.Id = dns.Id()

	r, rtt, err = c.Exchange(m, a)

	if err != nil {
		if *debug {
			fmt.Printf(";; %s\n", err.Error())
		}
		return
	}

	if r.Id != m.Id {
		if *debug {
			fmt.Fprintf(os.Stderr, "Id mismatch\n")
		}
		return r, rtt, errors.New("Id mismatch")
	}

	if r.MsgHdr.Truncated {
		// First EDNS, then TCP
		c.Net = "tcp"
		r, rtt, err = c.Exchange(m, a)
	}

	return
}
