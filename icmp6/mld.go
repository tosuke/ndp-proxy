package icmp6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type mldV1Message struct {
	MaximumResponseDelay uint16
	MulticastAddr        netip.Addr
}

var _ icmp.MessageBody = (*mldV1Message)(nil)

func (mldm *mldV1Message) Len(proto int) int {
	// Maximum Response Delay(16bit) + Reserved(16bit) Multicast Address(128bit)
	return 4 + 16
}

func (mldm *mldV1Message) Marshal(proto int) ([]byte, error) {
	// IPv6 only
	if proto != ipv6.ICMPTypeEchoReply.Protocol() {
		return nil, errInvalidProtocol
	}

	b := make([]byte, mldm.Len(proto))
	binary.BigEndian.PutUint16(b[0:2], mldm.MaximumResponseDelay)
	copy(b[4:], mldm.MulticastAddr.AsSlice())
	return b, nil
}

type MulticastListenerQuery struct {
	mldV1Message
}

type MulticastListenerReport struct {
	mldV1Message
}

type MulticastListenerDone struct {
	mldV1Message
}

func parseMLDv1Message(typ ipv6.ICMPType, b []byte) (icmp.MessageBody, error) {
	if len(b) != 20 {
		return nil, errors.New("invalid payload length")
	}

	maxRespDelay := binary.BigEndian.Uint16(b[0:2])

	maddr, err := unmarshalIPv6MulticastAddress(b[4:20])
	if err != nil {
		return nil, err
	}

	m := mldV1Message{
		MaximumResponseDelay: maxRespDelay,
		MulticastAddr:        maddr,
	}

	switch typ {
	case ipv6.ICMPTypeMulticastListenerQuery:
		return &MulticastListenerQuery{
			mldV1Message: m,
		}, nil
	case ipv6.ICMPTypeMulticastListenerReport:
		return &MulticastListenerReport{
			mldV1Message: m,
		}, nil
	case ipv6.ICMPTypeMulticastListenerDone:
		return &MulticastListenerDone{
			mldV1Message: m,
		}, nil
	default:
		return nil, fmt.Errorf("unknown message type(%s)", typ.String())
	}

}

type MulticastListenerQueryVersion2 struct {
	MaximumResponseDelay        uint
	MulticastAddr               netip.Addr
	SupressRouterSideProcessing bool
	Robustness                  uint // Querier's Robustness Variable
	QueryInterval               uint // Quewier's Query Interval
	SourceAddrs                 []netip.Addr
}

var _ icmp.MessageBody = (*MulticastListenerQueryVersion2)(nil)

func (m *MulticastListenerQueryVersion2) Len(proto int) int {
	return 4 + 16 + 4 + 16*len(m.SourceAddrs)
}

func (m *MulticastListenerQueryVersion2) Marshal(proto int) ([]byte, error) {
	// IPv6 only
	if proto != ipv6.ICMPTypeEchoReply.Protocol() {
		return nil, errInvalidProtocol
	}

	b := make([]byte, m.Len(proto))

	var maxRespCode uint16
	if m.MaximumResponseDelay < 32768 {
		maxRespCode = uint16(m.MaximumResponseDelay)
	} else {
		/*
		 * RFC3810, Section 5.1.3
		 *  0 1 2 3 4 5 6 7 8 9 A B C D E F
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 * |1| exp |          mant         |
		 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 */
		// 16 <= len <= 23
		len := bits.Len(m.MaximumResponseDelay)
		if len > 23 {
			return nil, errors.New("maximum response delay is too large")
		}

		low := len - 13
		mant := uint16(m.MaximumResponseDelay>>low) & 0xfff
		exp := uint16(low-3) & 0x7

		maxRespCode = 0x8000 | (exp << 12) | mant
	}
	binary.BigEndian.PutUint16(b[0:2], maxRespCode)

	if !m.MulticastAddr.Is6() {
		return nil, fmt.Errorf("multicast address %v is not IPv6", m.MulticastAddr)
	}
	if !m.MulticastAddr.IsMulticast() && m.MulticastAddr.Compare(zeroAddr) != 0 {
		return nil, fmt.Errorf("address %v is not multicast", m.MulticastAddr)
	}
	maddrBytes, err := m.MulticastAddr.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal multicast address(%v): %w", m.MulticastAddr, err)
	}
	copy(b[4:20], maddrBytes)

	var sqrv uint8
	if m.SupressRouterSideProcessing {
		sqrv |= 0x8
	}
	sqrv |= uint8(m.Robustness & 0x7)
	b[20] = sqrv

	var qqic uint8
	if m.QueryInterval < 128 {
		qqic = uint8(m.QueryInterval)
	} else {
		/*
		 * RFC3810, Section 5.1.9
		 *  0 1 2 3 4 5 6 7
		 * +-+-+-+-+-+-+-+-+
		 * |1| expt | mant |
		 * +-+-+-+-+-+-+-+-+
		 */
		// 8 <= len <= 15
		len := bits.Len(m.QueryInterval)
		if len > 15 {
			return nil, errors.New("query interval is too large")
		}

		low := len - 5
		mant := uint8(m.QueryInterval>>low) & 0xf
		exp := uint8(low-3) & 0x7

		qqic = 0x80 | (exp << 4) | mant
	}
	b[21] = qqic

	if len(m.SourceAddrs) > 65536 {
		return nil, errors.New("too many source addresses")
	}
	binary.BigEndian.PutUint16(b[22:24], uint16(len(m.SourceAddrs)))

	for i, addr := range m.SourceAddrs {
		if !addr.Is6() {
			return nil, fmt.Errorf("source address %v is not IPv address", addr)
		}
		if addr.IsMulticast() {
			return nil, fmt.Errorf("source address %v is not unicast", addr)
		}

		addrBytes, err := addr.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal source address %v: %s", addr, err)
		}

		copy(b[24+i*16:24+(i+1)*16], addrBytes)
	}

	return b, nil
}

func parseMLDv2Query(typ ipv6.ICMPType, b []byte) (icmp.MessageBody, error) {
	if len(b) < 20 {
		return nil, errors.New("invalid payload length(MLDv2 query length > 28)")
	}

	maxRespCode := uint(binary.BigEndian.Uint16(b[0:2]))
	var maxRespDelay uint
	if maxRespCode < 32768 {
		maxRespDelay = maxRespCode
	} else {
		exp := (maxRespCode >> 12) & 0x7
		mant := maxRespCode & 0xfff
		maxRespDelay = (mant | 0x1000) << (exp + 3)
	}

	maddr, err := unmarshalIPv6MulticastAddress(b[4:20])
	if err != nil {
		return nil, err
	}

	sFlag := b[20]&0x8 != 0
	robustness := uint(b[20] & 0x7)

	qqic := uint(b[21])
	var qqi uint
	if qqic < 128 {
		qqi = qqic
	} else {
		exp := (qqic >> 4) & 0x7
		mant := qqic & 0xf
		qqi = (mant | 0x10) << (exp + 3)
	}

	nSources := int(binary.BigEndian.Uint16(b[22:24]))

	sources := make([]netip.Addr, nSources)
	p := b[24:]
	for i := 0; i < nSources; i++ {
		saddr, err := unmarshalIPv6UnicastAddress(p[0:16])
		if err != nil {
			return nil, err
		}
		sources[i] = saddr
		p = p[16:]
	}

	return &MulticastListenerQueryVersion2{
		MaximumResponseDelay:        maxRespDelay,
		MulticastAddr:               maddr,
		SupressRouterSideProcessing: sFlag,
		Robustness:                  robustness,
		QueryInterval:               qqi,
		SourceAddrs:                 sources,
	}, nil
}

type MulticastListenerReportVersion2 struct {
	Records []MulticastAddressRecord
}

type MulticastAddressRecordType int

const (
	MulticastAddressRecordTypeModeIsInclude       MulticastAddressRecordType = 1
	MulticastAddressRecordTypeModeIsExclude       MulticastAddressRecordType = 2
	MulticastAddressRecordTypeChangeToIncludeMode MulticastAddressRecordType = 3
	MulticastAddressRecordTypeChangeToExcludeMode MulticastAddressRecordType = 4
	MulticastAddressRecordTypeAllowNewSources     MulticastAddressRecordType = 5
	MulticastAddressRecordTypeBlockOldSources     MulticastAddressRecordType = 6
)

var addressRecordTypes = map[MulticastAddressRecordType]string{
	MulticastAddressRecordTypeModeIsInclude:       "mode is include",
	MulticastAddressRecordTypeModeIsExclude:       "mode is exclude",
	MulticastAddressRecordTypeChangeToIncludeMode: "change to include mode",
	MulticastAddressRecordTypeChangeToExcludeMode: "change to exclude mode",
	MulticastAddressRecordTypeAllowNewSources:     "allow new sources",
	MulticastAddressRecordTypeBlockOldSources:     "block old sources",
}

func (typ MulticastAddressRecordType) String() string {
	s, ok := addressRecordTypes[typ]
	if !ok {
		return fmt.Sprintf("unknown(%d)", int(typ))
	}
	return s
}

type MulticastAddressRecord struct {
	Type             MulticastAddressRecordType
	MulticastAddress netip.Addr
	SourceAddresses  []netip.Addr
	AuxialiaryData   []byte
}

var _ icmp.MessageBody = (*MulticastListenerReportVersion2)(nil)

func (r *MulticastListenerReportVersion2) Len(proto int) int {
	return -1
}

func (r *MulticastListenerReportVersion2) Marshal(proto int) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func parseMLDv2Report(b []byte) (icmp.MessageBody, error) {
	nRecords := int(binary.BigEndian.Uint16(b[2:4]))
	p := b[4:]

	records := make([]MulticastAddressRecord, nRecords)
	for i := 0; i < nRecords; i++ {
		typ := MulticastAddressRecordType(p[0])
		auxDataLen := int(p[1]) * 4
		nSources := int(binary.BigEndian.Uint16(p[2:4]))

		maddr, err := unmarshalIPv6MulticastAddress(p[4:20])
		if err != nil {
			return nil, err
		}

		sources := make([]netip.Addr, nSources)
		p = p[20:]
		for j := 0; j < nSources; j++ {
			saddr, err := unmarshalIPv6UnicastAddress(p[0:16])
			if err != nil {
				return nil, err
			}
			sources[j] = saddr
			p = p[16:]
		}

		auxData := make([]byte, auxDataLen)
		copy(auxData, p[:auxDataLen])
		p = p[auxDataLen:]

		records[i] = MulticastAddressRecord{
			Type:             typ,
			MulticastAddress: maddr,
			SourceAddresses:  sources,
			AuxialiaryData:   auxData,
		}
	}

	return &MulticastListenerReportVersion2{
		Records: records,
	}, nil
}

func parseMLDMessage(typ ipv6.ICMPType, b []byte) (icmp.MessageBody, error) {
	switch typ {
	case ipv6.ICMPTypeMulticastListenerQuery:
		// ICMPv6 MLDv1 Query Message(28 bytes) - ICMPv6 Header(8 bytes)
		if len(b) != 20 {
			mb, err := parseMLDv2Query(typ, b)
			if err != nil {
				return nil, fmt.Errorf("failed to parse version 2 multicast listener query: %w", err)
			}
			return mb, err
		}
		fallthrough
	case ipv6.ICMPTypeMulticastListenerReport:
		fallthrough
	case ipv6.ICMPTypeMulticastListenerDone:
		mb, err := parseMLDv1Message(typ, b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse multicast listener message: %w", err)
		}
		return mb, err
	case ipv6.ICMPTypeVersion2MulticastListenerReport:
		mb, err := parseMLDv2Report(b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse version 2 multicast listener report: %w", err)
		}
		return mb, err
	default:
		return nil, fmt.Errorf("unknown message type(%s)", typ.String())
	}
}

var zeroAddr = netip.MustParseAddr("::")

func unmarshalIPv6MulticastAddress(b []byte) (netip.Addr, error) {
	var maddr netip.Addr
	maddr, ok := netip.AddrFromSlice(b)
	if !ok {
		return maddr, errors.New("failed to unmarshal address")
	}
	if !maddr.Is6() || maddr.Is4In6() {
		return maddr, fmt.Errorf("multicast address %v is not IPv6 address", maddr)
	}
	if !maddr.IsMulticast() && maddr.Compare(zeroAddr) != 0 {
		return maddr, fmt.Errorf("multicast address %v is not multicast address", maddr)
	}

	return maddr, nil
}

func unmarshalIPv6UnicastAddress(b []byte) (netip.Addr, error) {
	var addr netip.Addr
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return addr, errors.New("failed to unmarshal address")
	}
	if !addr.Is6() || addr.Is4In6() {
		return addr, fmt.Errorf("address %v is not IPv6 address", addr)
	}
	if !addr.IsGlobalUnicast() && !addr.IsLinkLocalUnicast() {
		return addr, fmt.Errorf("multicast address %v is not unicast address", addr)
	}
	return addr, nil
}
