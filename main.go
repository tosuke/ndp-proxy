package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/tosuke/ndp-proxy/icmp6"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [upstream interface] [downstream interface]\n\nOptions\n", os.Args[0])
		flag.PrintDefaults()
	}

	var showHelp bool
	flag.BoolVarP(&showHelp, "help", "h", false, "show this message")

	var runAsMLDQuerier bool
	flag.BoolVarP(&runAsMLDQuerier, "mld-querier", "", false, "run as MLD querier")

	flag.Parse()

	if showHelp {
		flag.Usage()
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) != 2 {
		flag.Usage()
		os.Exit(1)
	}

	ifs := make([]*net.Interface, 0, len(args))
	for _, name := range args {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to find interface %s: %v\n", name, err)
			os.Exit(1)
		}
		ifs = append(ifs, ifi)
	}

	upIf := ifs[0]
	downIf := ifs[1]

	as := NewAddrState()

	ndpproxy := &NDPProxy{
		UpIf:      upIf,
		DownIf:    downIf,
		AddrEvent: as,
	}

	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		err := listenMLD(ctx, downIf, runAsMLDQuerier, as)
		if err != nil {
			return fmt.Errorf("failed to listen MLD: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		err := ndpproxy.Run(ctx)
		if err != nil {
			return fmt.Errorf("failed to run NDP proxy: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		log.Fatal(err)
	}
}

func listenMLD(ctx context.Context, ifi *net.Interface, querier bool, ac AddrCollector) error {
	lc := &net.ListenConfig{}
	c, err := lc.ListenPacket(ctx, "ip6:ipv6-icmp", "::")
	if err != nil {
		return fmt.Errorf("failed to listen ICMP6: %w", err)
	}
	defer c.Close()
	p := ipv6.NewPacketConn(c)

	if err := p.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagInterface, true); err != nil {
		return fmt.Errorf("failed to set control message: %w", err)
	}

	filter, err := p.ICMPFilter()
	if err != nil {
		return fmt.Errorf("failed to get ICMP filter: %w", err)
	}

	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeMulticastListenerQuery)
	filter.Accept(ipv6.ICMPTypeMulticastListenerReport)
	filter.Accept(ipv6.ICMPTypeMulticastListenerDone)
	filter.Accept(ipv6.ICMPTypeVersion2MulticastListenerReport)

	if err := p.SetICMPFilter(filter); err != nil {
		return fmt.Errorf("failed to set ICMP filter: %w", err)
	}

	group := &net.IPAddr{IP: net.ParseIP("ff02::16")}
	if err := p.JoinGroup(ifi, group); err != nil {
		return fmt.Errorf("failed to join MLD multicast group: %w", err)
	}
	defer p.LeaveGroup(ifi, group)

	log.Printf("MLD: listen on %s", ifi.Name)

	eg, ctx := errgroup.WithContext(ctx)

	querierCtx, cancelQuerier := context.WithCancel(ctx)

	if querier {
		eg.Go(func() error {
			log.Printf("MLD: run as querier")

			interval := 60
			tick := time.Tick(time.Duration(interval) * time.Second)

			for {
				err := sendMLDQuery(ctx, ifi, p, interval)
				if err != nil {
					log.Printf("MLD: failed to send query: %v", err)
				}

				select {
				case <-tick:

				case <-querierCtx.Done():
					return nil
				}
			}
		})
	}

	eg.Go(func() error {
		errChan := make(chan error)
		go func() {
			for {
				rb := make([]byte, 1500)
				n, rcm, srcAddr, err := p.ReadFrom(rb)
				if err != nil {
					errChan <- fmt.Errorf("failed to read from socket: %w", err)
					return
				}

				go func() {
					if rcm.IfIndex != ifi.Index {
						return
					}

					m, err := icmp6.ParseMessage(ipv6.ICMPTypeMulticastListenerReport.Protocol(), rb[:n])
					if err != nil {
						log.Printf("failed to parse MLD message: %v", err)
						return
					}

					if querier && m.Type == ipv6.ICMPTypeMulticastListenerQuery {
						srcIP := srcAddr.(*net.IPAddr)
						src, ok := netip.AddrFromSlice(srcIP.IP)
						if !ok {
							return
						}
						if srcIP.Zone != "" {
							src = src.WithZone(srcIP.Zone)
						}

						lladdr, err := findLinkLocalAddr(ifi)
						if err != nil {
							log.Printf("failed to find link local address: %v", err)
							return
						}

						log.Printf("detect MLD querier on %s", src)
						if src.Compare(lladdr) < 0 {
							cancelQuerier()
						}
					}

					switch mb := m.Body.(type) {
					case *icmp6.MulticastListenerReport:
						if isSolicitatedNodeMulticastAddress(mb.MulticastAddr) {
							ac.Join(mb.MulticastAddr)
						}
					case *icmp6.MulticastListenerDone:
						if isSolicitatedNodeMulticastAddress(mb.MulticastAddr) {
							ac.Leave(mb.MulticastAddr)
						}
					case *icmp6.MulticastListenerReportVersion2:
						for _, r := range mb.Records {
							if !isSolicitatedNodeMulticastAddress(r.MulticastAddress) {
								continue
							}
							switch r.Type {
							case icmp6.MulticastAddressRecordTypeModeIsExclude:
								if len(r.SourceAddresses) == 0 {
									ac.Join(r.MulticastAddress)
								}
							case icmp6.MulticastAddressRecordTypeChangeToExcludeMode:
								if len(r.SourceAddresses) == 0 {
									ac.Join(r.MulticastAddress)
								}
							}
						}
					default:
						break
					}
				}()
			}
		}()

		select {
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return nil
		}
	})

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed to listen MLD: %w", err)
	}
	return nil
}

func sendMLDQuery(ctx context.Context, ifi *net.Interface, p *ipv6.PacketConn, interval int) error {
	dst := netip.MustParseAddr("ff02::1").WithZone(ifi.Name)

	wm := icmp.Message{
		Type: ipv6.ICMPTypeMulticastListenerQuery,
		Code: 0,
		Body: &icmp6.MulticastListenerQueryVersion2{
			MaximumResponseDelay:        10000,
			MulticastAddr:               netip.MustParseAddr("::"),
			SupressRouterSideProcessing: false,
			Robustness:                  2,
			QueryInterval:               uint(interval),
		},
	}
	wcm := ipv6.ControlMessage{
		HopLimit: 255,
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal MLD query: %w", err)
	}

	if _, err := p.WriteTo(wb, &wcm, &net.IPAddr{IP: dst.AsSlice(), Zone: dst.Zone()}); err != nil {
		return fmt.Errorf("failed to send MLD query: %w", err)
	}

	return nil
}

func findLinkLocalAddr(ifi *net.Interface) (netip.Addr, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.IsLinkLocalUnicast() {
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ip = ip.WithZone(ifi.Name)
			return ip, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("failed to find link local address")
}

var solicitatedNodeMulticastAddressPrefix = netip.MustParsePrefix("ff02::1:ff00:0/104")

func isSolicitatedNodeMulticastAddress(addr netip.Addr) bool {
	return solicitatedNodeMulticastAddressPrefix.Contains(addr)
}
