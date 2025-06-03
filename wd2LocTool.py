#!/usr/bin/env python3
# ============================================================================
#  Watch-Dogs .loc   Universal Decoder / Encoder
#  -------------------------------------------------
#  Windows-only · Python 3.9+ · PyQt6 GUI + CLI
# ============================================================================
import os, sys, struct, collections, argparse, ctypes
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QGridLayout, QPushButton,
    QLineEdit, QLabel, QRadioButton, QButtonGroup, QFileDialog,
    QMessageBox
)
from PyQt6.QtCore import Qt

# ----------------------------------------------------------------------------
#  Exceptions
# ----------------------------------------------------------------------------
class LocError(Exception):
    """Raised for any parsing inconsistency."""

# ----------------------------------------------------------------------------
#  Helpers
# ----------------------------------------------------------------------------
def _u16(buf, off): return struct.unpack_from('<H', buf, off)[0]
def _u32(buf, off): return struct.unpack_from('<I', buf, off)[0]

# ----------------------------------------------------------------------------
#  Bitstream helpers (unchanged)
# ----------------------------------------------------------------------------
class BitWriter:
    def __init__(self): self.buf, self.acc, self.bits = bytearray(), 0, 0
    def write(self, code: int, length: int):
        while length:
            take = min(8 - self.bits, length)
            self.acc |= ((code >> (length - take)) & ((1 << take) - 1)) << (8 - self.bits - take)
            self.bits += take; length -= take
            if self.bits == 8:
                self.buf.append(self.acc); self.acc = self.bits = 0
    def get(self) -> bytes:  # align & return
        if self.bits: self.buf.append(self.acc)
        return bytes(self.buf)

class BitReader:
    def __init__(self, data: bytes): self.data, self.pos, self.acc, self.bits = data, 0, 0, 0
    def read(self, n: int) -> int:
        while self.bits < n:
            if self.pos >= len(self.data): raise EOFError('bitstream truncated')
            self.acc = (self.acc << 8) | self.data[self.pos]; self.pos += 1; self.bits += 8
        self.bits -= n
        return (self.acc >> self.bits) & ((1 << n) - 1)

# ----------------------------------------------------------------------------
#  Canonical Huffman builder
# ----------------------------------------------------------------------------
def build_huffman(freq: dict):
    if 0 not in freq: freq[0] = 1
    q = [(f, [s]) for s, f in freq.items()]; q.sort(key=lambda t: t[0])
    while len(q) > 1:
        f1, s1 = q.pop(0); f2, s2 = q.pop(0)
        ins = (f1 + f2, s1 + s2)
        idx = next((i for i, (f, _) in enumerate(q) if f > ins[0]), len(q))
        q.insert(idx, ins)
    root = q[0][1]
    length = {s: 0 for s in root}
    stack = [(root, 0)]
    while stack:
        syms, depth = stack.pop()
        if len(syms) == 1:
            length[syms[0]] = depth
        else:
            mid = len(syms) // 2
            stack.append((syms[:mid], depth + 1))
            stack.append((syms[mid:], depth + 1))
    ordering = sorted((length[s], s) for s in root)
    code, prev_len, book = 0, ordering[0][0], {}
    for l, s in ordering:
        code <<= (l - prev_len); book[s] = (code, l); code += 1; prev_len = l
    nodes = []
    def add_node(symset):
        idx = len(nodes)
        if len(symset) == 1:
            nodes.append(symset[0])
        else:
            mid = len(symset) // 2
            left = add_node(symset[:mid]); right = add_node(symset[mid:])
            nodes.append((left << 16) | right)
        return idx
    add_node(root)
    return book, nodes

# ----------------------------------------------------------------------------
#  Universal .loc reader
# ----------------------------------------------------------------------------
def read_loc(path: str):
    data = open(path, 'rb').read()
    if data[:2] != b'SL':
        raise LocError('missing "SL" magic')
    version = _u16(data, 2)
    if version not in (0, 1):
        raise LocError(f'unsupported version {version}')

    file_size = len(data)

    # --- 1. treeOffset ------------------------------------------------------
    tree_off = _u32(data, 8)
    if tree_off < 0x14 or tree_off + 4 > file_size:
        raise LocError(f'bad tree offset {tree_off:#x}')

    # --- 2. nodeCount candidates -------------------------------------------
    cand_cnt = []

    # v1 layout: nodeCount = *(tree_off - 4)
    if tree_off >= 4:
        cand_cnt.append(_u32(data, tree_off - 4))

    # v0 layout: nodeCount stored at 0x0C
    cand_cnt.append(_u32(data, 0x0C))

    # remove zeros / dups
    cand_cnt = [c for c in dict.fromkeys(cand_cnt) if c]

    # pick first valid
    tree_cnt = next((c for c in cand_cnt if tree_off + c * 4 <= file_size), None)

    # fallback brute-force (last resort)
    if tree_cnt is None:
        guess = (file_size - tree_off) // 4
        if guess > 0:
            tree_cnt = guess
        else:
            raise LocError('cannot determine node count')

    # --- 3. dataOffset ------------------------------------------------------
    data_off = tree_off + tree_cnt * 4
    if data_off > file_size:
        raise LocError('computed data offset beyond file size')

    # --- 4. tableCount & table array start ----------------------------------
    table_cnt = _u16(data, 6)           # v1
    tbl_pos   = 0x10                    # v1 start
    if tbl_pos + table_cnt * 4 > tree_off - 4:  # overlap? try v0
        table_cnt = _u32(data, 0x1C)
        tbl_pos   = 0x20
        if tbl_pos + table_cnt * 4 > tree_off - 4:
            raise LocError('table array truncated / overlaps tree')

    # --- 5. build ID list ---------------------------------------------------
    ids, pos = [], tbl_pos
    for _ in range(table_cnt):
        n = _u32(data, pos); pos += 4
        ids.extend(range(len(ids), len(ids) + n))

    # --- 6. decode strings --------------------------------------------------
    nodes = struct.unpack_from(f'<{tree_cnt}I', data, tree_off)
    br = BitReader(data[data_off:])
    def d_char():
        idx = tree_cnt - 1
        while nodes[idx] > 0xFFFF:
            left, right = nodes[idx] >> 16, nodes[idx] & 0xFFFF
            idx = left if br.read(1) == 0 else right
        return nodes[idx]

    strings = []
    for _ in ids:
        out = []
        while True:
            c = d_char()
            if c == 0: break
            out.append(chr(c))
        strings.append(''.join(out))

    header = data[:tree_off]  # preserved for re-encode
    return ids, strings, header

# ----------------------------------------------------------------------------
#  Writer (same as前)
# ----------------------------------------------------------------------------
def write_loc(ids, strings, header, out_path):
    if len(ids) != len(strings):
        raise LocError('ID / string count mismatch')
    freq = collections.Counter()
    for s in strings: freq.update(ord(c) for c in s); freq[0] += 1
    book, nodes = build_huffman(freq)
    bw = BitWriter()
    for s in strings:
        for ch in s:
            code, l = book[ord(ch)]; bw.write(code, l)
        code0, l0 = book[0]; bw.write(code0, l0)

    tree_off = len(header)
    if tree_off & 3: raise LocError('header not 4-byte aligned')

    tree_cnt = len(nodes)
    hdr = bytearray(header)
    struct.pack_into('<III', hdr, 8, tree_off, _u32(header, 12), tree_off + tree_cnt * 4)
    with open(out_path, 'wb') as fp:
        fp.write(hdr)
        fp.write(struct.pack(f'<{tree_cnt}I', *nodes))
        fp.write(bw.get())

# ----------------------------------------------------------------------------
#  CLI
# ----------------------------------------------------------------------------
def cli():
    ap = argparse.ArgumentParser('loc_tool')
    sub = ap.add_subparsers(dest='cmd', required=True)
    d = sub.add_parser('decode'); d.add_argument('loc');  d.add_argument('txt')
    e = sub.add_parser('encode'); e.add_argument('txt');  e.add_argument('base'); e.add_argument('loc')
    sub.add_parser('gui')
    args = ap.parse_args()
    try:
        if args.cmd == 'decode':
            ids, strs, _ = read_loc(args.loc)
            with open(args.txt, 'w', encoding='utf-16le') as fp:
                for i, s in zip(ids, strs): fp.write(f'{i}\t{s}\n')
            print(f'Decoded {len(ids)} strings → {args.txt}')
        elif args.cmd == 'encode':
            ids, strings = [], []
            with open(args.txt, 'r', encoding='utf-16le') as fp:
                for ln in fp:
                    if not ln.strip(): continue
                    sep = '\t' if '\t' in ln else '='
                    i, s = ln.split(sep, 1)
                    ids.append(int(i.strip())); strings.append(s.rstrip('\n'))
            _, _, hdr = read_loc(args.base)
            write_loc(ids, strings, hdr, args.loc)
            print(f'Encoded {len(ids)} strings → {args.loc}')
        else:
            gui()
    except LocError as e:
        print(f'Error: {e}')
        sys.exit(1)

# ----------------------------------------------------------------------------
#  PyQt6 GUI
# ----------------------------------------------------------------------------
class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Watch-Dogs .loc Tool')
        self._build(); self.setAcceptDrops(True)

    def _build(self):
        w = QWidget(); self.setCentralWidget(w); g = QGridLayout(w)

        self.rb_dec = QRadioButton('Decode (.loc → .txt)'); self.rb_dec.setChecked(True)
        self.rb_enc = QRadioButton('Encode (.txt → .loc)')
        grp = QButtonGroup(self); grp.addButton(self.rb_dec); grp.addButton(self.rb_enc)
        grp.buttonToggled.connect(self._mode)

        # path edits
        self.ed_in   = QLineEdit(); self.ed_out  = QLineEdit(); self.ed_base = QLineEdit()
        self.ed_in .setToolTip('Input file (.loc for decode, .txt for encode)')
        self.ed_out.setToolTip('Output file (.txt for decode, .loc for encode)')
        self.ed_base.setToolTip('Original .loc template (required for Encode)')

        # buttons
        btn_in  = QPushButton('Input…');  btn_in .clicked.connect(self._pick_in)
        btn_out = QPushButton('Output…'); btn_out.clicked.connect(self._pick_out)
        self.btn_base = QPushButton('Base LOC…'); self.btn_base.clicked.connect(self._pick_base)
        run = QPushButton('Run'); run.clicked.connect(self._run)
        uac = QPushButton('🛡 Elevate'); uac.clicked.connect(self._elevate)
        run.setToolTip('Start decoding / encoding'); uac.setToolTip('Restart as administrator')

        help_lbl = QLabel('CLI: decode <loc> <txt> | encode <txt> <base.loc> <loc> | gui')
        help_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        note_lbl = QLabel('Encoding **requires** original .loc for metadata / Huffman tree.')

        g.addWidget(self.rb_dec, 0,0); g.addWidget(self.rb_enc, 0,1); g.addWidget(uac, 0,3)
        g.addWidget(btn_in , 1,0); g.addWidget(self.ed_in , 1,1,1,2)
        g.addWidget(btn_out, 2,0); g.addWidget(self.ed_out, 2,1,1,2)
        g.addWidget(self.btn_base, 3,0); g.addWidget(self.ed_base,3,1,1,2)
        g.addWidget(run, 4,0,1,2); g.addWidget(help_lbl,5,0,1,4)
        g.addWidget(note_lbl, 6,0,1,4)

        self._mode()

    def _mode(self):  # show / hide base row
        enc = self.rb_enc.isChecked()
        self.btn_base.setVisible(enc); self.ed_base.setVisible(enc)

    # ---------------------------------------------------------------- drag-n-drop
    def dragEnterEvent(self, e):  # accept any file
        if e.mimeData().hasUrls(): e.acceptProposedAction()
    def dropEvent(self, e):
        path = e.mimeData().urls()[0].toLocalFile()
        ext  = os.path.splitext(path)[1].lower()
        if ext == '.loc':
            self.rb_dec.setChecked(True); self.ed_in.setText(path)
            self.ed_out.setText(os.path.splitext(path)[0] + '.txt')
        elif ext == '.txt':
            self.rb_enc.setChecked(True); self.ed_in.setText(path)
            self.ed_out.setText(os.path.splitext(path)[0] + '_mod.loc')
            guess = os.path.splitext(path)[0] + '.loc'
            if os.path.isfile(guess): self.ed_base.setText(guess)
        self._mode()

    # ---------------------------------------------------------------- pickers
    def _pick_in(self):
        p, _ = QFileDialog.getOpenFileName(self, 'Select input', filter='LOC (*.loc);;TXT (*.txt)')
        if p: self.ed_in.setText(p)
    def _pick_out(self):
        filt = 'TXT (*.txt)' if self.rb_dec.isChecked() else 'LOC (*.loc)'
        p, _ = QFileDialog.getSaveFileName(self, 'Select output', filter=filt)
        if p: self.ed_out.setText(p)
    def _pick_base(self):
        p, _ = QFileDialog.getOpenFileName(self, 'Select base .loc', filter='LOC (*.loc)')
        if p: self.ed_base.setText(p)

    # ---------------------------------------------------------------- elevate
    def _elevate(self):
        try:
            params = ' '.join(f'"{a}"' for a in sys.argv if a.lower() != 'gui')
            ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, params, None, 1); sys.exit()
        except Exception as e:
            QMessageBox.critical(self, 'Elevation failed', str(e))

    # ---------------------------------------------------------------- run
    def _run(self):
        mode = 'decode' if self.rb_dec.isChecked() else 'encode'
        inp, out, base = self.ed_in.text().strip(), self.ed_out.text().strip(), self.ed_base.text().strip()
        if not inp or not out or (mode == 'encode' and not base):
            QMessageBox.warning(self, 'Missing', 'Fill required paths'); return
        try:
            if mode == 'decode':
                ids, strs, _ = read_loc(inp)
                with open(out, 'w', encoding='utf-16le') as fp:
                    for i, s in zip(ids, strs): fp.write(f'{i}\t{s}\n')
                QMessageBox.information(self, 'Done', f'{len(ids)} strings decoded.')
            else:
                ids, strings = [], []
                with open(inp, 'r', encoding='utf-16le') as fp:
                    for ln in fp:
                        if not ln.strip(): continue
                        sep = '\t' if '\t' in ln else '='
                        i, s = ln.split(sep, 1)
                        ids.append(int(i.strip())); strings.append(s.rstrip('\n'))
                _, _, hdr = read_loc(base)
                write_loc(ids, strings, hdr, out)
                QMessageBox.information(self, 'Done', f'{len(ids)} strings encoded.')
        except LocError as e:
            QMessageBox.critical(self, 'Parse error', str(e))
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

# ----------------------------------------------------------------------------
def gui():
    app = QApplication(sys.argv)
    m = Main(); m.resize(800, 240); m.show()
    sys.exit(app.exec())

# ----------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] not in ('gui',):
        cli()
    else:
        gui()
