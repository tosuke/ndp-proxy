package icmp6

import (
	"encoding/binary"
	"errors"
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
	// TODO: handle options

	// Reserved(32bit) + Target Address(128bit)
	return 4 + 16
}

func (ns *NeighborSolicitation) Marshal(proto int) ([]byte, error) {
	// IPv6 only
	if proto != ipv6.ICMPTypeEchoReply.Protocol() {
		return nil, errInvalidProtocol
	}

	b := make([]byte, ns.Len(proto))
	b[0] = 0
	copy(b[4:], ns.TargetAddr.AsSlice())
	return b, nil
}

func parseNeighborSolicitation(typ icmp.Type, b []byte) (icmp.MessageBody, error) {
	if typ != ipv6.ICMPTypeNeighborSolicitation {
		return nil, errInvalidProtocol
	}

	reserved := binary.BigEndian.Uint32(b[0:4])
	if reserved != 0 {
		return nil, errors.New("invalid reserved field")
	}

	targetAddr, ok := netip.AddrFromSlice(b[4:20])
	if !ok {
		return nil, errors.New("invalid target address")
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
