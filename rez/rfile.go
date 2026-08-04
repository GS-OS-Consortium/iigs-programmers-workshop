package rez

import (
	"encoding/binary"
	"sort"
)

// Apple IIgs resource file layout, per GSToolbox/ResourceMgr/Resource.a and
// confirmed byte-for-byte against RezIIGS's own output:
//
//	rFileVersion  long   = 0
//	rFileToMap    long   = $8C (the header is 12 bytes + a 128-byte memo)
//	rFileMapSize  long
//	rFileMemo     byte[128]   -- zero as RezIIGS writes it; the filename and
//	                             type/creator seen in shipped files are put
//	                             there later, by the Finder or a copy tool
//	map:
//	  mapNext        long  = 0
//	  mapFlag        word  = 0
//	  mapOffset      long  = $8C
//	  mapSize        long
//	  mapToIndex     word  = $74
//	  mapFileNum     word  = 0
//	  mapID          word  = 0
//	  mapIndexSize   long  -- slots allocated (used + 10)
//	  mapIndexUsed   long
//	  mapFreeListSize word = 10
//	  mapFreeListUsed word = 1
//	  BLOCK[10]           -- 8 bytes each: blkOffset, blkSize
//	  long           = 0   -- the NIL terminator the "NIL terminates" comment
//	                          in Resource.a refers to
//	  index[mapIndexSize] -- 20 bytes each
//	then the resource data, in SOURCE order.
const (
	rFileHeaderSize = 0x8C // 12 + 128
	mapHeaderSize   = 0x20 // through mapFreeListUsed, where the blocks start
	freeListSlots   = 10
	mapToIndex      = mapHeaderSize + freeListSlots*8 + 4 // $74
	indexEntrySize  = 20
	indexSlack      = 10 // RezIIGS allocates ten spare index slots
	indexTermSize   = 2  // a zero word closes the index, as NIL closes the free list
)

// Build assembles a resource fork from the compiled resources.
func Build(res []Resource) []byte {
	idxSize := len(res) + indexSlack
	mapSize := mapToIndex + idxSize*indexEntrySize + indexTermSize
	dataStart := rFileHeaderSize + mapSize

	// Resource data is laid out in SOURCE order...
	data := make([]byte, 0, 64*1024)
	offs := make([]int, len(res))
	for i := range res {
		offs[i] = dataStart + len(data)
		data = append(data, res[i].Data...)
	}
	total := dataStart + len(data)

	// ...while the index is sorted by type then id.
	order := make([]int, len(res))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := res[order[a]], res[order[b]]
		if x.Type != y.Type {
			return x.Type < y.Type
		}
		return x.ID < y.ID
	})

	out := make([]byte, total)
	le := binary.LittleEndian
	le.PutUint32(out[0:], 0)               // rFileVersion
	le.PutUint32(out[4:], rFileHeaderSize) // rFileToMap
	le.PutUint32(out[8:], uint32(mapSize)) // rFileMapSize
	// rFileMemo stays zero

	m := rFileHeaderSize
	le.PutUint32(out[m+0x00:], 0)                // mapNext
	le.PutUint16(out[m+0x04:], 0)                // mapFlag
	le.PutUint32(out[m+0x06:], rFileHeaderSize)  // mapOffset
	le.PutUint32(out[m+0x0A:], uint32(mapSize))  // mapSize
	le.PutUint16(out[m+0x0E:], mapToIndex)       // mapToIndex
	le.PutUint16(out[m+0x10:], 0)                // mapFileNum
	le.PutUint16(out[m+0x12:], 0)                // mapID
	le.PutUint32(out[m+0x14:], uint32(idxSize))  // mapIndexSize
	le.PutUint32(out[m+0x18:], uint32(len(res))) // mapIndexUsed
	le.PutUint16(out[m+0x1C:], freeListSlots)    // mapFreeListSize
	le.PutUint16(out[m+0x1E:], 1)                // mapFreeListUsed
	// One free block covering everything past EOF: offset = end of file,
	// size = the rest of the 32-bit space (offset+size == $FFFFFFFF).
	le.PutUint32(out[m+0x20:], uint32(total))
	le.PutUint32(out[m+0x24:], uint32(0xFFFFFFFF-total))

	ip := m + mapToIndex
	for n, i := range order {
		r := res[i]
		p := ip + n*indexEntrySize
		le.PutUint16(out[p+0:], uint16(r.Type))
		le.PutUint32(out[p+2:], uint32(r.ID))
		le.PutUint32(out[p+6:], uint32(offs[i]))
		le.PutUint16(out[p+10:], r.Attrs)
		le.PutUint32(out[p+12:], uint32(len(r.Data)))
		le.PutUint32(out[p+16:], 0) // handle, zero on disk
	}

	copy(out[dataStart:], data)
	return out
}
