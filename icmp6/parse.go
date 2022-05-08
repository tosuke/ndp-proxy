package icmp6

import (
	"fmt"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

func ParseMessage(proto int, b []byte) (*icmp.Message, error) {
	m, err := icmp.ParseMessage(proto, b)
	if err != nil {
		return nil, err
	}

	rb, ok := m.Body.(*icmp.RawBody)
	if !ok {
		return m, nil
	}

	var mb icmp.MessageBody
	var err2 error
	switch m.Type {
	case ipv6.ICMPTypeNeighborSolicitation:
		mb, err2 = parseNeighborSolicitation(rb.Data)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse neighbor solicitation: %s", err2)
		}
	case ipv6.ICMPTypeNeighborAdvertisement:
		mb, err2 = parseNeighborAdvertisement(rb.Data)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse neighbor advertisement: %w", err2)
		}
	case ipv6.ICMPTypeMulticastListenerQuery:
		fallthrough
	case ipv6.ICMPTypeMulticastListenerReport:
		fallthrough
	case ipv6.ICMPTypeMulticastListenerDone:
		fallthrough
	case ipv6.ICMPTypeVersion2MulticastListenerReport:
		mb, err2 = parseMLDMessage(m.Type.(ipv6.ICMPType), rb.Data)
	default:
		mb = rb
	}
	if err2 != nil {
		return nil, err2
	}

	return &icmp.Message{
		Type:     m.Type,
		Code:     m.Code,
		Checksum: m.Checksum,
		Body:     mb,
	}, nil
}
