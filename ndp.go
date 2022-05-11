package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"

	"github.com/tosuke/ndp-proxy/icmp6"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

type NDPProxy struct {
	Control   func(p *ipv6.PacketConn) error
	UpIf      *net.Interface
	DownIf    *net.Interface
	AddrEvent AddrEvent
	requests  map[netip.Addr]request
}

type request struct {
	addr netip.Addr
	src  net.Addr
}

func (np *NDPProxy) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if np.UpIf == nil {
		return fmt.Errorf("no interface")
	}

	if np.requests == nil {
		np.requests = make(map[netip.Addr]request)
	}

	lc := &net.ListenConfig{}
	c, err := lc.ListenPacket(ctx, "ip6:ipv6-icmp", "::")
	if err != nil {
		return fmt.Errorf("failed to listen ICMP6: %w", err)
	}
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	p := ipv6.NewPacketConn(c)

	if err := p.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagInterface, true); err != nil {
		return fmt.Errorf("failed to set control message: %w", err)
	}

	filter := &ipv6.ICMPFilter{}
	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeNeighborSolicitation)
	filter.Accept(ipv6.ICMPTypeNeighborAdvertisement)

	if err := p.SetICMPFilter(filter); err != nil {
		return fmt.Errorf("failed to set ICMP filter: %w", err)
	}

	if np.Control != nil {
		if err := np.Control(p); err != nil {
			return fmt.Errorf("failed to control PacketConn: %w", err)
		}
	}

	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		err := speakMLD(ctx, np.UpIf, p, np.AddrEvent)
		if err != nil {
			return fmt.Errorf("failed to speak MLD: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		for {
			rb := make([]byte, 1500)
			n, rcm, src, err := p.ReadFrom(rb)
			if err != nil {
				select {
				case <-ctx.Done():
					return nil
				default:
					return fmt.Errorf("failed to read from socket: %w", err)
				}
			}

			go func() {
				if err := np.handle(p, rb[:n], rcm, src); err != nil {
					log.Printf("NDP: failed to handle ICMP6 packet: %v", err)
				}
			}()
		}
	})

	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

func (np *NDPProxy) handle(p *ipv6.PacketConn, rb []byte, rcm *ipv6.ControlMessage, src net.Addr) error {
	m, err := icmp6.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), rb)
	if err != nil {
		return fmt.Errorf("failed to parse ICMP6 message: %w", err)
	}

	switch mb := m.Body.(type) {
	case *icmp6.NeighborSolicitation:
		if rcm.IfIndex != np.UpIf.Index {
			return nil
		}
		log.Printf("NDP: received solicitation from %s: who is %s", src, mb.TargetAddr)
	}

	return nil
}

func speakMLD(ctx context.Context, ifi *net.Interface, p *ipv6.PacketConn, ae AddrEvent) error {
	log.Printf("MLD: speak on %s", ifi.Name)

	joinedAddrs := make(map[netip.Addr]struct{})

	for {
		select {
		case addr, ok := <-ae.Joined():
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
