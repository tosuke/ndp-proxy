package icmp6

import (
	"errors"
	"net"
)

var (
	errInvalidOptionType = errors.New("invalid option type")
)

type NDPOptionType int

const (
	NDPOptionSourceLinkLayerAddress NDPOptionType = 1
	NDPOptionTargetLinkLayerAddress NDPOptionType = 2
)

var ndpOptionTypes = map[NDPOptionType]string{
	NDPOptionSourceLinkLayerAddress: "source link-layer address",
	NDPOptionTargetLinkLayerAddress: "target link-layer address",
}

func (typ NDPOptionType) String() string {
	s, ok := ndpOptionTypes[typ]
	if !ok {
		return "<nil>"
	}
	return s
}

type NDPOptions = []NDPOption

type NDPOption struct {
	Type NDPOptionType
	Body NDPOptionBody
}

func (o *NDPOption) Len() int {
	return 2 + o.Body.Len()
}

func (o *NDPOption) Marshal() ([]byte, error) {
	len := o.Len()

	if len%8 != 0 {
		return nil, errors.New("invalid option length")
	}

	b := make([]byte, len)
	b[0] = byte(o.Type)
	b[1] = byte(len / 8)

	if o.Body != nil && o.Body.Len() > 0 {
		ob, err := o.Body.Marshal()
		if err != nil {
			return nil, err
		}
		copy(b[2:], ob)
	}

	return b, nil
}

type NDPOptionBody interface {
	Len() int
	Marshal() ([]byte, error)
}

// Raw option body
type RawNDPOptionBody struct {
	Data []byte
}

func (p *RawNDPOptionBody) Len() int {
	return len(p.Data)
}

func (p *RawNDPOptionBody) Marshal() ([]byte, error) {
	return p.Data, nil
}

// Source Link-layer Address
type SourceLinkLayerAddress struct {
	HardwareAddr net.HardwareAddr
}

var _ NDPOptionBody = (*SourceLinkLayerAddress)(nil)

func (p *SourceLinkLayerAddress) Len() int {
	return paddingBodyLen(len(p.HardwareAddr))
}

func (p *SourceLinkLayerAddress) Marshal() ([]byte, error) {
	b := make([]byte, p.Len())
	copy(b[:], p.HardwareAddr)
	return b, nil
}

// Target Link-layer Address
type TargetLinkLayerAddress struct {
	HardwareAddr net.HardwareAddr
}

var _ NDPOptionBody = (*TargetLinkLayerAddress)(nil)

func (p *TargetLinkLayerAddress) Len() int {
	return paddingBodyLen(len(p.HardwareAddr))
}

func (p *TargetLinkLayerAddress) Marshal() ([]byte, error) {
	b := make([]byte, p.Len())
	copy(b[:], p.HardwareAddr)
	return b, nil
}

func parseLinkLayerAddressOption(typ NDPOptionType, b []byte) (NDPOptionBody, error) {
	var ab []byte
	switch len(b) {
	case 6: // 48-bit MAC address
		ab = make([]byte, 6)
		copy(ab, b[:])
	case 14: // EUI-64
		ab = make([]byte, 8)
		copy(ab, b[:8])
	case 22: // IPoIB
		ab = make([]byte, 20)
		copy(ab, b[:20])
	default:
		ab = make([]byte, len(b))
		copy(ab, b)
	}

	hwa := net.HardwareAddr(ab)

	if typ == NDPOptionSourceLinkLayerAddress {
		return &SourceLinkLayerAddress{HardwareAddr: hwa}, nil
	} else {
		return nil, errInvalidOptionType
	}
}

func parseOptions(b []byte) (NDPOptions, error) {
	var opts NDPOptions
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errors.New("invalid option length")
		}

		typ := NDPOptionType(b[0])
		l := int(b[1]) * 8
		if l < 2 || l > len(b) {
			return nil, errors.New("invalid option length")
		}

		bb := b[2:l]

		var body NDPOptionBody
		var err error
		switch typ {
		case NDPOptionSourceLinkLayerAddress, NDPOptionTargetLinkLayerAddress:
			body, err = parseLinkLayerAddressOption(typ, bb)
		default:
			body = &RawNDPOptionBody{Data: bb}
		}
		if err != nil {
			return nil, err
		}

		opts = append(opts, NDPOption{Type: typ, Body: body})
		b = b[l:]
	}

	return opts, nil
}

func paddingBodyLen(len int) int {
	return ((len+2)/8)*8 - 2
}
