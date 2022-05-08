package icmp6

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

var (
	errInvalidProtocol = errors.New("invalid protocol")
)

type NeighborSolicitation struct {
	TargetAddr netip.Addr
	Options    NDPOptions
}

var _ icmp.MessageBody = (*NeighborSolicitation)(nil)

func (ns *NeighborSolicitation) Len(proto int) int {
	var ol int
	for _, o := range ns.Options {
		ol += o.Len()
	}

	// Reserved(32bit) + Target Address(128bit)
	return 4 + 16 + ol
}

func (ns *NeighborSolicitation) Marshal(proto int) ([]byte, error) {
	// IPv6 only
	if proto != ipv6.ICMPTypeEchoReply.Protocol() {
		return nil, errInvalidProtocol
	}

	b := make([]byte, ns.Len(proto))
	b[0] = 0

	if ns.TargetAddr.IsMulticast() {
		return nil, errors.New("target address must not be multicast")
	}
	addrBytes, err := ns.TargetAddr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(b[4:], addrBytes)

	p := b[20:]
	for _, o := range ns.Options {
		ol := o.Len()
		bytes, err := o.Marshal()
		if err != nil {
			return nil, err
		}

		copy(p[:ol], bytes[:ol])
		p = p[ol:]
	}

	return b, nil
}

func parseNeighborSolicitation(b []byte) (icmp.MessageBody, error) {
	if len(b) < 20 {
		return nil, errors.New("invalid message length")
	}

	targetAddr, err := unmarshalIPv6UnicastAddress(b[4:20])
	if err != nil {
		return nil, err
	}

	options, err := parseOptions(b[20:])
	if err != nil {
		return nil, err
	}

	return &NeighborSolicitation{
		TargetAddr: targetAddr,
		Options:    options,
	}, nil
}

type NeighborAdvertisement struct {
	RouterFlag    bool
	SolicitedFlag bool
	OverrideFlag  bool
	TargetAddress netip.Addr
	Options       NDPOptions
}

var _ icmp.MessageBody = (*NeighborAdvertisement)(nil)

func (na *NeighborAdvertisement) Len(proto int) int {
	var ol int
	for _, o := range na.Options {
		ol += o.Len()
	}

	return 4 + 16 + ol
}

func (na *NeighborAdvertisement) Marshal(proto int) ([]byte, error) {
	// IPv6 only
	if proto != ipv6.ICMPTypeEchoReply.Protocol() {
		return nil, errInvalidProtocol
	}

	b := make([]byte, na.Len(proto))

	var b0 byte
	if na.RouterFlag {
		b0 |= 0x80
	}
	if na.SolicitedFlag {
		b0 |= 0x40
	}
	if na.OverrideFlag {
		b0 |= 0x20
	}
	b[0] = b0

	if na.TargetAddress.IsMulticast() {
		return nil, errors.New("target address must not be multicast")
	}
	addrBytes, err := na.TargetAddress.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal target address: %w", err)
	}
	copy(b[4:], addrBytes)

	p := b[20:]
	for _, o := range na.Options {
		l := o.Len()

		bytes, err := o.Marshal()
		if err != nil {
			return nil, err
		}

		copy(p[:l], bytes[:l])
		p = p[l:]
	}

	return b, nil
}

func parseNeighborAdvertisement(b []byte) (icmp.MessageBody, error) {
	if len(b) < 20 {
		return nil, errors.New("invalid message length")
	}

	var routerFlag, solicitedFlag, overrideFlag bool
	if b[0]&0x80 != 0 {
		routerFlag = true
	}
	if b[0]&0x40 != 0 {
		solicitedFlag = true
	}
	if b[0]&0x20 != 0 {
		overrideFlag = true
	}

	targetAddr, err := unmarshalIPv6UnicastAddress(b[4:20])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal target address: %w", err)
	}

	options, err := parseOptions(b[20:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse options: %w", err)
	}

	return &NeighborAdvertisement{
		RouterFlag:    routerFlag,
		SolicitedFlag: solicitedFlag,
		OverrideFlag:  overrideFlag,
		TargetAddress: targetAddr,
		Options:       options,
	}, nil
}
