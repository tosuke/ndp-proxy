package main

import "net/netip"

type AddrCollector interface {
	Join(addr netip.Addr)
	Leave(addr netip.Addr)
}

type AddrEvent interface {
	Joined() chan netip.Addr
	Leaved() chan netip.Addr
}

type AddrState struct {
	joined chan netip.Addr
	leaved chan netip.Addr
}

func NewAddrState() *AddrState {
	return &AddrState{
		joined: make(chan netip.Addr, 100),
		leaved: make(chan netip.Addr, 100),
	}
}

func (as *AddrState) Join(addr netip.Addr) {
	as.joined <- addr
}

func (as *AddrState) Leave(addr netip.Addr) {
	as.leaved <- addr
}

func (as *AddrState) Joined() chan netip.Addr {
	return as.joined
}

func (as *AddrState) Leaved() chan netip.Addr {
	return as.leaved
}
