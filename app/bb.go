package app

import (
	cs "github.com/er1cw00/btx.go/asm/cs"
)

var ErrorExistBB = errors.New("BB is exist")

type BB struct {
	Start uint64
	Size  uint64
	Insn  []*cs.Instruction
	Next  uint64
	Left  uint64
	Right uint64
}

const BB_INVALID uint64 = 0

type BBGraph struct {
	name   string
	start  uint64
	size   uint64
	insn   []*cs.Instruction
	rootBB uint64
	listBB []uint64
	mapBB  map[uint64]*BB
}

func NewBBG(name string, start, size uint64, insn []*cs.Instruction) *BBGraph {
	bbg := &BBGraph{
		name:   name,
		start:  start,
		end:    end,
		insn:   insn,
		rootBB: BB_INVALID,
		mapBB:  make(map[uint64]*BB),
		listBB: make([]uint64, 0),
	}
	return bbg
}

func (g *BBGraph) FindBB(start uint64) *BB {
	if bb, found := g.mapBB[start]; found {
		return bb
	}
	return nil
}
func (g *BBGraph) InsertBB(bb *BB) error {
	if _, found := g.mapBB[bb.start]; found {
		return ErrorExistBB
	}

	for i := 1; i < len(g.listBB); i++ {
		prevBB := g.listBB[i-1]
		currBB := g.listBB[i]
		if prevBB.start == bb.Start {

		}
	}
}
func NewBB(start, size uint64) *BB {
	bb := &BB{
		Start: start,
		Size:  0,
		Insn:  nil,
		Next:  BB_INVALID,
		Left:  BB_INVALID,
		Right: BB_INVALID,
	}
	g.mapBB[start] = bb

	return nil
}
