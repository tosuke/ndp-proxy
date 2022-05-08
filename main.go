package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"

	"github.com/tosuke/ndp-proxy/icmp6"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var ifi *net.Interface
	flag.Func("i", "`interface` to run NDP proxy", func(name string) (err error) {
		ifi, err = net.InterfaceByName(name)
		return
	})

	var ifiMLD *net.Interface
	flag.Func("m", "`interface` to listen MLD", func(name string) (err error) {
		ifiMLD, err = net.InterfaceByName(name)
		return
	})

	flag.Parse()

	if ifi == nil || ifiMLD == nil {
		flag.Usage()

		if ifi == nil {
			fmt.Println("-i is required")
		}
		if ifiMLD == nil {
			fmt.Println("-m is required")
		}
		os.Exit(1)
	}

	joinChan := make(chan netip.Addr)
	defer close(joinChan)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return listenMLD(ctx, ifiMLD, joinChan)
	})
	eg.Go(func() error {
		return speakMLD(ctx, ifi, joinChan)
	})

	if err := eg.Wait(); err != nil {
		log.Fatal(err)
	}
}

func findLinkLocalAddr(ifi *net.Interface) (netip.Addr, error) {
	var lladdr netip.Addr

	addrs, err := ifi.Addrs()
	if err != nil {
		return lladdr, err
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}

		if addr.IsLinkLocalUnicast() {
			lladdr = addr.WithZone(ifi.Name)
			return lladdr, nil
		}
	}

	return lladdr, errors.New("no link-local address found")
}

func listenMLD(ctx context.Context, ifi *net.Interface, joinChan chan netip.Addr) error {
	lladdr, err := findLinkLocalAddr(ifi)
	if err != nil {
		return fmt.Errorf("failed to find link-local address of %s: %w", ifi.Name, err)
	}

	c, err := net.ListenPacket("ip6:ipv6-icmp", lladdr.String())
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer c.Close()

	p := ipv6.NewPacketConn(c)

	filter, err := p.ICMPFilter()
	if err != nil {
		return fmt.Errorf("failed to get ICMP filter: %w", err)
	}

	filter.SetAll(true)
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

	errChan := make(chan error)
	go func() {
		for {
			rb := make([]byte, 1500)
			n, _, _, err := p.ReadFrom(rb)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from socket: %w", err)
				return
			}

			go func() {
				m, err := icmp6.ParseMessage(ipv6.ICMPTypeMulticastListenerReport.Protocol(), rb[:n])
				if err != nil {
					log.Printf("failed to parse MLD message: %v", err)
					return
				}

				switch mb := m.Body.(type) {
				case *icmp6.MulticastListenerReport:
					if isSolicitatedNodeMulticastAddress(mb.MulticastAddress) {
						joinChan <- mb.MulticastAddress
					}
				case *icmp6.MulticastListenerDone:
					break
				case *icmp6.MulticastListenerReportVersion2:
					for _, r := range mb.Records {
						if !isSolicitatedNodeMulticastAddress(r.MulticastAddress) {
							continue
						}
						switch r.Type {
						case icmp6.MulticastAddressRecordTypeModeIsExclude:
							if len(r.SourceAddresses) == 0 {
								joinChan <- r.MulticastAddress
							}
						case icmp6.MulticastAddressRecordTypeChangeToExcludeMode:
							if len(r.SourceAddresses) == 0 {
								joinChan <- r.MulticastAddress
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
}

func speakMLD(ctx context.Context, ifi *net.Interface, joinChan chan netip.Addr) error {
	lladdr, err := findLinkLocalAddr(ifi)
	if err != nil {
		return fmt.Errorf("failed to find link-local address of %s: %w", ifi.Name, err)
	}

	c, err := net.ListenPacket("ip6:ipv6-icmp", lladdr.String())
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer c.Close()

	p := ipv6.NewPacketConn(c)

	log.Printf("MLD: speak on %s", ifi.Name)

	joinedAddrs := make(map[netip.Addr]struct{})
	defer func() {
		for addr := range joinedAddrs {
			group := &net.IPAddr{IP: addr.AsSlice()}
			if err := p.LeaveGroup(ifi, group); err != nil {
				log.Printf("failed to leave MLD multicast group: %v", err)
			}
		}
	}()

	for {
		select {
		case addr, ok := <-joinChan:
			if !ok {
				break
			}

			if !isSolicitatedNodeMulticastAddress(addr) {
				continue
			}

			_, has := joinedAddrs[addr]
			if !has {
				group := &net.IPAddr{IP: addr.AsSlice()}
				if err := p.JoinGroup(ifi, group); err != nil {
					return fmt.Errorf("failed to join MLD multicast group: %w", err)
				}
				joinedAddrs[addr] = struct{}{}
				log.Printf("MLD: joined %s", addr)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

var solicitatedNodeMulticastAddressPrefix = netip.MustParsePrefix("ff02::1:ff00:0/104")

func isSolicitatedNodeMulticastAddress(addr netip.Addr) bool {
	return solicitatedNodeMulticastAddressPrefix.Contains(addr)
}
