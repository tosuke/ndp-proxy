package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/tosuke/ndp-proxy/icmp6"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

type NDPProxy struct {
	Control   func(p *ipv6.PacketConn) error
	UpIf      *net.Interface
	DownIf    *net.Interface
	AddrEvent AddrEvent
	requests  requests
}

type request struct {
	addr     netip.Addr
	src      netip.Addr
	deadline time.Time
}

func (np *NDPProxy) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if np.UpIf == nil {
		return fmt.Errorf("no interface")
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

func (np *NDPProxy) handle(p *ipv6.PacketConn, rb []byte, rcm *ipv6.ControlMessage, srcAddr net.Addr) error {
	m, err := icmp6.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), rb)
	if err != nil {
		return fmt.Errorf("failed to parse ICMP6 message: %w", err)
	}

	srcIPAddr, ok := srcAddr.(*net.IPAddr)
	if !ok {
		return fmt.Errorf("invalid source address type: %v", srcAddr)
	}
	src, ok := netip.AddrFromSlice(srcIPAddr.IP)
	if !ok {
		return fmt.Errorf("invalid source address: %v", srcIPAddr)
	}
	if srcIPAddr.Zone != "" {
		src = src.WithZone(srcIPAddr.Zone)
	}

	switch mb := m.Body.(type) {
	case *icmp6.NeighborSolicitation:
		if rcm.IfIndex != np.UpIf.Index {
			return nil
		}
		if !mb.TargetAddr.IsGlobalUnicast() || !mb.TargetAddr.Is6() {
			return nil
		}

		target := mb.TargetAddr.AsSlice()
		var matchedIf *net.Interface
		addrs, err := np.DownIf.Addrs()
		if err != nil {
			return fmt.Errorf("failed to get interface addresses: %w", err)
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.IsGlobalUnicast() && ipnet.Contains(target) {
				matchedIf = np.DownIf
				break
			}
		}
		if matchedIf == nil {
			return nil
		}

		log.Printf("NDP: handle  solicit from %s: who is %s", src, mb.TargetAddr)

		deadline := time.Now().Add(2 * time.Second)
		req := request{
			src:      src,
			addr:     mb.TargetAddr,
			deadline: deadline,
		}
		np.requests.Add(req)

		srcLinkLayerAddrOption := icmp6.NDPOption{
			Type: icmp6.NDPOptionSourceLinkLayerAddress,
			Body: &icmp6.SourceLinkLayerAddress{
				HardwareAddr: matchedIf.HardwareAddr,
			},
		}

		wm := icmp.Message{
			Type: ipv6.ICMPTypeNeighborSolicitation,
			Code: 0,
			Body: &icmp6.NeighborSolicitation{
				TargetAddr: mb.TargetAddr,
				Options:    []icmp6.NDPOption{srcLinkLayerAddrOption},
			},
		}
		wcm := ipv6.ControlMessage{
			HopLimit: 255,
		}

		wb, err := wm.Marshal(nil)
		if err != nil {
			return fmt.Errorf("failed to marshal NS message: %w", err)
		}

		dst := net.ParseIP("ff02::1:ff00:0")
		copy(dst[13:16], target[13:16])

		if _, err := p.WriteTo(wb, &wcm, &net.IPAddr{IP: dst, Zone: matchedIf.Name}); err != nil {
			return fmt.Errorf("failed to write NS message: %w", err)
		}

	case *icmp6.NeighborAdvertisement:
		if rcm.IfIndex != np.DownIf.Index {
			return nil
		}

		req, has := np.requests.Get(mb.TargetAddr)
		if !has {
			return nil
		}
		np.requests.Remove(req.src, req.addr)

		log.Printf("NDP: respond solicit from %s: who is %s", req.src, req.addr)

		targetLLAddrOption := icmp6.NDPOption{
			Type: icmp6.NDPOptionTargetLinkLayerAddress,
			Body: &icmp6.TargetLinkLayerAddress{
				HardwareAddr: np.UpIf.HardwareAddr,
			},
		}
		wm := icmp.Message{
			Type: ipv6.ICMPTypeNeighborAdvertisement,
			Code: 0,
			Body: &icmp6.NeighborAdvertisement{
				TargetAddr:    mb.TargetAddr,
				RouterFlag:    false,
				SolicitedFlag: mb.SolicitedFlag,
				OverrideFlag:  mb.OverrideFlag,
				Options:       []icmp6.NDPOption{targetLLAddrOption},
			},
		}
		wcm := ipv6.ControlMessage{
			HopLimit: 255,
		}

		wb, err := wm.Marshal(nil)
		if err != nil {
			return fmt.Errorf("failed to marshal NA message: %w", err)
		}

		if _, err := p.WriteTo(wb, &wcm, &net.IPAddr{IP: req.src.AsSlice(), Zone: req.src.Zone()}); err != nil {
			return fmt.Errorf("failed to write NA message: %w", err)
		}
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

type requests struct {
	m map[netip.Addr]request
}

const maxRequests = 1000

func (r *requests) Add(req request) {
	if r.m == nil {
		r.m = make(map[netip.Addr]request)
	}

	if len(r.m) >= maxRequests {
		r.gc()
	}

	if req.deadline.After(time.Now()) {
		r.m[req.addr] = req
	}
}

func (r *requests) Remove(src netip.Addr, addr netip.Addr) {
	if r.m == nil {
		return
	}

	delete(r.m, addr)
}

func (r *requests) Get(addr netip.Addr) (request, bool) {
	if r.m == nil {
		return request{}, false
	}

	req, has := r.m[addr]
	if !has {
		return request{}, false
	}
	if req.deadline.Before(time.Now()) {
		r.Remove(req.src, req.addr)
		return request{}, false
	}
	return req, true
}

func (r *requests) gc() {
	for addr, req := range r.m {
		if req.deadline.Before(time.Now()) {
			delete(r.m, addr)
		}
	}
}
