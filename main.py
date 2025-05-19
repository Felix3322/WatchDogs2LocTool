#!/usr/bin/env python3
# Watch Dogs 1/2/Legion .loc → .txt pure-python extractor
# Author: Monday (ChatGPT) · 2025-05-19
# 100 % API-compatible复刻 https://github.com/ahmet-celik/watch-dogs-loc-tool (C#)
# ----------------------------------------------------------

import io, os, struct, sys
from collections import deque

# ---------- helpers ----------
def u8(b, o):   return b[o]
def u16(b, o):  return struct.unpack_from('<H', b, o)[0]
def s16(b, o):  return struct.unpack_from('<h', b, o)[0]
def u32(b, o):  return struct.unpack_from('<I', b, o)[0]
def be32(b, o): return struct.unpack_from('>I', b, o)[0]

class R(io.BytesIO):
    """Byte-level reader with LE helpers & BigEndian U32 for bit-stream."""
    def read_u8 (self): return u8 (self._buf, self._inc(1))
    def read_u16(self): return u16(self._buf, self._inc(2))
    def read_s16(self): return s16(self._buf, self._inc(2))
    def read_u32(self): return u32(self._buf, self._inc(4))
    def read_be32(self):return be32(self._buf, self._inc(4))
    # ------- internal -------
    def __init__(self, data): super().__init__(data); self._buf = data
    def _inc(self, n): p=self.tell(); self.seek(p+n); return p

# ---------- core structures ----------
class Id:
    __slots__=('id','lo','hi','is_pseudo')
    def __init__(self, base): self.id=base; self.lo=1; self.hi=0; self.is_pseudo=False

    # translate C# Id.Read()
    def read(self, r: R, k_ref, bits_ref):
        k      = k_ref[0]
        bits   = bits_ref[0]
        sz     = r.read_u8()
        if sz>0xF0:              # pseudo-ID -> 跳过
            k        += sz-240
            self.is_pseudo=True
        else:
            if   sz==0xF0:
                sz = ((r.read_u8()<<8)+r.read_u8()) + 5340
            elif sz>=0xDC:
                sz = ((sz<<8)+r.read_u8()) - 56100
            if sz: sz = sz*2+4
            self.lo = bits
            bits   += sz
            self.hi = bits
        k_ref [0]=k+1 if not self.is_pseudo else k
        bits_ref[0]=bits

class SubTableMeta:
    __slots__=('max_id','size','delta')
    def __init__(self): self.max_id=self.size=self.delta=0
    def read(self,r:R):
        first,second = r.read_u16(), r.read_u16()
        whole        = (first<<16)+second
        self.delta   = second
        if whole>=0x80000000:
            self.size = r.read_u16()
            if (whole>>30)&1:
                self.delta += r.read_u16()<<16
            self.max_id = first & 0x3FFF
        else:
            self.max_id = first>>7
            self.size   = (whole>>12)&0x7FF
            self.delta &= 0xFFF

class LocFile:
    def __init__(self, data: bytes): self.r = R(data); self._read()

    # ---------- high-level API ----------
    def export_txt(self, out):
        with open(out,'w',encoding='utf-16le',newline='') as fo:
            for tbl in self.tables:
                for block in tbl['ids']:
                    for ent in block:
                        if ent.is_pseudo:          continue
                        bl = ent.hi-ent.lo
                        if bl==0:
                            text = ''
                        else:
                            text = self._decode_string(tbl, ent)
                        fo.write(f"{ent.id}={text.replace(chr(13),'[CR]').replace(chr(10),'[LF]')}\n")

    # ---------- internal ----------
    def _read(self):
        r=self.r
        magic,ver = r.read_s16(), r.read_s16()
        if (magic,ver)!=(0x4C53,1): raise SystemExit("Not a WD .loc file / wrong version")
        self.language     = r.read_s16()
        tbl_count         = r.read_u16()
        self.tree_offset  = r.read_u32()

        # -- read tables header first (C# keeps stream cursor) --
        tbl_headers=[]
        for _ in range(tbl_count):
            first_id     = r.read_u32()
            off_len      = r.read_u32()
            tbl_headers.append((first_id, off_len>>4, off_len&0xF))

        # -- parse each table fully (metas+ids) --
        self.tables=[]
        end_of_tables = -1
        for first_id,off,length in tbl_headers:
            r.seek(off)
            # sub-meta
            metas=[SubTableMeta() for _ in range(length)]
            for m in metas:m.read(r)
            # ids
            sub_ids=[]
            block_first=first_id
            block_pos  = r.tell()
            for mi,m in enumerate(metas):
                r.seek(block_pos)
                sub_ids.append(self._read_sub_ids(r, block_pos, block_first, m))
                block_first += m.max_id+1
                block_pos   += m.size
            self.tables.append({'ids':sum(sub_ids,[]), 'start':off})   # flattened list
            end_of_tables=max(end_of_tables,block_pos)

        # -- tree meta & nodes (shared for whole file) --
        r.seek( (end_of_tables+3)&~3 )
        tree_meta_len = (self.tree_offset - r.tell())>>2
        self.tree_meta=[0]*tree_meta_len
        for i in range(tree_meta_len):
            self.tree_meta[tree_meta_len-i-1]=r.read_u32()
        self.nodes_count=r.read_u32()

    def _read_sub_ids(self,r:R,start,first_id,meta:SubTableMeta):
        ids=[]
        total=meta.max_id+1
        blk_cnt=(total-1)>>6
        blk_off=[r.read_u16() for _ in range(blk_cnt)]
        j=0
        while j<total:
            if j>=64 and j%64==0:
                off=blk_off[(j>>6)-1]
                if off==0:             # whole block skipped
                    j+=64; continue
                r.seek(start+off)
            k=[0]
            bits=[0]
            block=[]
            while k[0]<min(total-j,64):
                ent=Id(first_id+j+k[0])
                ent.read(r,k,bits)
                block.append(ent)
            # adjust bit offsets
            delta=((r.tell()-start)<<3)
            for ent in block:
                ent.lo+=delta; ent.hi+=delta
            ids.append(block); j+=64
        return ids

    # -------------- bitstream → UTF-16 decode --------------
    def _decode_string(self, tbl, ent):
        r=self.r
        bit_len   = ent.hi-ent.lo
        byte_off  = tbl['start'] + (ent.lo>>3)
        bit_left  = ent.lo & 7
        r.seek(byte_off)
        cur_uint  = r.read_be32() << bit_left
        byte_off += 4

        out=[]
        while bit_len>0:
            pos,bit_len,cur_uint,byte_off,bit_left = self._traverse_tree(
                r,bit_len,cur_uint,byte_off,bit_left)
            self._dfs_decode(pos,out)
        return bytes(out).decode('utf-16le')

    def _traverse_tree(self,r,bit_len,cur_uint,byte_off,bit_left):
        m=self.tree_meta
        masked = cur_uint & 0xFFFFFFE0
        was24  = False
        if masked>=m[6]:
            if masked>=m[8]:
                if masked>=m[10]:
                    raise SystemExit("Tree decode error")
                was24=True; bit_len-=24
                pos = m[11] + (masked>>8)
                cur_uint <<=24; bit_left+=16
            else:
                bit_len-=16; pos=m[9]+(masked>>16); cur_uint<<=16; bit_left+=8
        else:
            if masked>=m[2]:
                if masked>=m[4]:
                    bit_len-=14; pos=m[7]+(masked>>18); cur_uint<<=14; bit_left+=6
                else:
                    bit_len-=12; pos=m[5]+(masked>>20); cur_uint<<=12; bit_left+=4
            else:
                if masked>=m[0]:
                    bit_len-=10; pos=m[3]+(masked>>22); cur_uint<<=10; bit_left+=2
                else:
                    bit_len-=8;  pos=m[1]+(masked>>24); cur_uint<<=8
        # refill shift-register
        if not was24:
            r.seek(byte_off); cur_uint+=r.read_u8()<<bit_left; byte_off+=1
        if bit_left>=8:
            bit_left-=8; cur_uint+=r.read_u8()<<bit_left; byte_off+=1
        return pos,bit_len,cur_uint,byte_off,bit_left

    def _dfs_decode(self,pos,out):
        r=self.r; stack=[pos]
        while stack:
            idx=stack.pop()
            r.seek(self.tree_offset+4*idx)
            node=r.read_u32()
            if node<=0xFFFF:          # leaf → UTF-16 code-unit
                out.extend(struct.pack('<H',node))
            else:                     # internal → push children (big-endian order)
                stack.append(node>>16)
                stack.append(node & 0xFFFF)

# ---------- CLI ----------
def main():
    if len(sys.argv)!=2 or not sys.argv[1].lower().endswith('.loc'):
        sys.exit("Usage: python wd2_loc_decode.py <file.loc>")
    loc_path = sys.argv[1]
    with open(loc_path,'rb') as f: data=f.read()
    loc = LocFile(data)
    out = loc_path + '.txt'
    loc.export_txt(out)
    print(f'✓ extracted → {out}')

if __name__ == '__main__':
    main()
