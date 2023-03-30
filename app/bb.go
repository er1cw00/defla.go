package app

import (
	"errors"
	cs "github.com/er1cw00/btx.go/asm/cs"
)

var ErrorExistBB = errors.New("BB is exist")

type BB struct {
	Start uint64
	End   uint64
	Insn  []*cs.Instruction
	Next  uint64
	Left  uint64
	Right uint64
}

const BB_INVALID uint64 = 0

type BBGraph struct {
	name   string
	base   uint64
	size   uint64
	insn   []*cs.Instruction
	rootBB uint64
	mapBB  map[uint64]*BB
	listBB []uint64
}

func NewBBG(name string, base, size uint64, insn []*cs.Instruction) *BBGraph {
	bbg := &BBGraph{
		name:   name,
		base:   base,
		size:   size,
		insn:   insn,
		rootBB: BB_INVALID,
		mapBB:  make(map[uint64]*BB),
		listBB: make([]uint64, 0),
	}
	return bbg
}

func NewBB(start, end uint64) *BB {
	bb := &BB{
		Start: start,
		End:   end,
		Insn:  nil,
		Next:  BB_INVALID,
		Left:  BB_INVALID,
		Right: BB_INVALID,
	}

	return bb
}
