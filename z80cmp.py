#!/usr/bin/python3

import z80table as z
from difflib import SequenceMatcher
from pathlib import Path
from bisect import bisect_right
from collections import namedtuple, Counter
import argparse
import json

markings = [
    [None,],  # OP_NONE
    [None, z.OP_BYTE],  # OP_BYTE
    [None, z.OP_WORD, z.OP_WORD],  # OP_WORD
    [None, z.OP_OFFSET],  # OP_OFFSET
    [None, z.OP_JUMP, z.OP_JUMP],  # OP.JUMP
    [z.opcodes_CB],  # OP.CB
    [z.opcodes_DD],  # OP.DD
    [z.opcodes_ED],  # OP.ED
    [z.opcodes_FD],  # OP.DD
    [None, z.OP_BYTE_OFF],  # BYTE_OFF
    [None, z.OP_BYTE_OFF_2, z.OP_BYTE_OFF_2],  # BYTE_OFF_2
    [z.opcodes_DDCB],  # OP_DDCB
    [z.opcodes_FDCB],  # OP_FDCB
    [None, z.OP_BYTE_OFF_3, z.OP_NONE]
]


Skeleton = namedtuple("Skeleton", "addr data disasm")
DisasmData = namedtuple("DisasmData", "decoded optype oploc")


def get_role(d):
    role = [-1] * len(d)
    i = 0
    table = z.opcodes_main
    disasm = {}
    while i < len(d):

        role[i] = z.OP_NONE
        optype, dec = table[d[i]]
        if table == z.opcodes_main:
            addr = i
        mark = markings[optype]
        if mark[0] is None:
            for j in range(1, len(mark)):
                role[i+j] = mark[j]
            # lab = f"{dec}".ljust(10)
            # print(f"  {lab} ;{addr:04x}")
            disasm[addr] = DisasmData(dec, optype, i)
            table = z.opcodes_main
        else:
            table = mark[0]
        i += len(mark)
    return role, disasm


def get_skeleton(d):
    role, disasm = get_role(d)
    addr = []
    data = []
    for a, (b, r) in enumerate(zip(d, role)):
        if r in [z.OP_NONE]:
            addr.append(a)
            data.append(b)
    return Skeleton(addr, data, disasm)


def format_matrix(matrix):
    result = "[\n"
    for row in matrix:
        result += "  " + str(row) + ",\n"
    result = result.rstrip(",\n") + "\n]"  # Remove the last comma
    return result


def address_mapping_oneway(addr_a, data_a, addr_b, data_b):

    matcher = SequenceMatcher(None, data_a, data_b)

    # Get matching blocks
    matches = matcher.get_matching_blocks()

    # Create mappings
    a_to_b = {}
    b_to_a = {}

    totmatches = 0
    for match in matches:
        data_a_start, data_b_start, size = match
        totmatches += size
        for i in range(size):
            a = addr_a[data_a_start + i]
            b = addr_b[data_b_start + i]
            a_to_b[a] = b
            b_to_a[b] = a

    return a_to_b, b_to_a, totmatches


def address_mapping(addr_a, data_a, addr_b, data_b):
    m1, m1r, m1n = address_mapping_oneway(addr_a, data_a, addr_b, data_b)
    m2, m2r, m2n = address_mapping_oneway(addr_b, data_b, addr_a, data_a)

    if m1n >= m2n:
        return m1, m1r, m1n
    else:
        return m2r, m2, m2n


def sig8(x):
    if x > 127:
        x -= 256
    return x


def little_endian(x):
    return sum([v*(1 << (8*i)) for i, v in enumerate(x)])


def char_rep(x):
    if 32 <= x <= 126:
        return chr(x)
    return "."


def format_chunk(c):
    num = " ".join([f"{x:02X}" for x in c]).ljust(14)
    asc = " ".join(char_rep(x) for x in c)
    return num+asc


def count_equalities(cs):
    ok = 0
    for i, ci in enumerate(cs):
        for j, cj in enumerate(cs):
            if i != j and ci == cj:
                ok += 1
    return ok


class AddressSplitter:
    def __init__(self, bases):
        self.bases = sorted(bases)

    def decompose(self, x):
        idx = bisect_right(self.bases, x)
        base = self.bases[idx - 1] if idx > 0 else 0
        return base, x-base


class AddressConverter(AddressSplitter):
    def __init__(self, conv):
        super().__init__(conv.keys())
        self.conv = conv

    def convert(self, a):
        base, off = self.decompose(a)
        return self.conv[base]+off


class IdentityConverter(AddressSplitter):

    def __init__(self, conv):
        super().__init__(conv.keys())

    def convert(self, a):
        return a


class Disassember:

    def __init__(self, fnames):
        self.fnames = fnames
        self.ds = [open(f, "rb").read() for f in fnames]
        self.n = len(fnames)
        self.sk = [get_skeleton(d) for d in self.ds]
        self.aconversion = [[None for _ in fnames] for _ in fnames]
        self.matchmatrix = [[0 for _ in fnames] for _ in fnames]
        self.labels = [{} for _ in fnames]
        self.equlabels = [{} for _ in fnames]
        for i in range(self.n):
            self.aconversion[i][i] = IdentityConverter(self.sk[i].disasm)
            self.matchmatrix[i][i] = len(self.sk[i].addr)
            for j in range(i+1, self.n):
                print(
                    f"Computing similarities of {self.fnames[i]} " +
                    f"to {self.fnames[j]}")
                m, mr, mn = address_mapping(self.sk[i].addr, self.sk[i].data,
                                            self.sk[j].addr, self.sk[j].data)

                self.aconversion[i][j] = AddressConverter(m)
                self.aconversion[j][i] = AddressConverter(mr)
                self.matchmatrix[i][j] = self.matchmatrix[j][i] = mn
        self.equmap = [[{} for _ in fnames] for _ in fnames]
        self.formatters = [
            self.f_none,  # NONE
            self.f_byte,  # BYTE
            self.f_word,  # WORD
            self.f_offset,  # OFFSET
            self.f_jump,  # JUMP
            self.f_none,  # CB
            self.f_none,  # DD
            self.f_none,  # ED
            self.f_none,  # DD
            self.f_byte_off,  # BYTE_OFF
            self.f_byte_off_2,  # BYTE_OFF_2
            self.f_none,  # OP_DDCB
            self.f_none,  # OF_FDCB
            self.f_byte_off  # OP_BYTE_OFF_3
        ]
        print("Generating labels")
        self.generate_labels()
        print("Aligning files")
        self.align()

    def align_repr(self, a, i):
        # if self.isROM(a, i):
        return tuple(self.aconvs(a, i))
        # else:
        #    return tuple(a,)

    def getDeltas(self, i):
        ias = self.aconversion[i][i].bases+sorted(self.equlabels[i].keys())

        addlab = {a: self.align_repr(a, i) for a in ias}
        deltas = {}
        for a, na in zip(ias, ias[1:]):
            step = 2 if a in self.labels[i] else 1
            deltas[addlab[na]] = (addlab[a], step)
        return deltas

    def align(self):
        deltas = {}
        for i in range(self.n):
            d = self.getDeltas(i)
            for na, (pa, s) in d.items():
                deltas.setdefault(na, {}).setdefault(pa, 1)
                deltas[na][pa] = max(deltas[na][pa], s)
        self.row = {}

        def compRow(a):
            if a in self.row:
                return self.row[a]
            row = 0
            if a in deltas:
                for pa, da in deltas[a].items():
                    row = max(row, compRow(pa)+da)
            self.row[a] = row
            return row
        alignerr = 0
        for na in sorted(deltas):
            try:
                compRow(na)
            except RecursionError:
                # a = "_".join([f"{x:04x}" for x in na])
                # print(f"Loop detected for address {a}")
                if len(self.row.keys()) == 0:
                    self.row[na] = 0
                else:
                    self.row[na] = max(self.row.values())+2
                alignerr += 1
        if alignerr:
            print(f"Alignment errors, count {alignerr}")

    def equconv(self, a, i, j):
        if a in self.equmap[i][j]:
            d = self.equmap[i][j][a]
            k = max(d, key=d.get)
            if d[k] > 1:
                return k
        return a

    def isROM(self, a, i):
        return a < len(self.ds[i])

    def aconv(self, a, i, j):
        if self.isROM(a, i):
            return self.aconversion[i][j].convert(a)
        else:
            return self.equconv(a, i, j)

    def aconvs(self, a, i):
        ac = [self.aconv(a, i, j) for j in range(self.n)]
        return ac

    def get_address_repr(self, a, i):
        return "_".join([f"{a:04X}" for a in self.aconvs(a, i)])

    def get_label(self, a, i):
        return "l"+self.get_address_repr(a, i)

    def f_none(self, a, i):
        return []

    def f_byte(self, a, i):
        return [f"0{self.ds[i][a+1]:02X}h"]

    def count_matches(self, vs, i):
        valm = max(Counter(vs).values())
        addr = [self.aconv(v, j, i) for j, v in enumerate(vs)]
        addrm = max(Counter(addr).values())
        return valm, addrm

    def base_label(self, v, i):

        base, off = self.aconversion[i][i].decompose(v)
        offlab = "" if off == 0 else f"+{off}"
        lab = self.get_label(base, i)
        if self.phase == 0:
            self.labels[i][base] = lab
        return lab+offlab

    def store_equ(self, vs, i):
        a = vs[i]
        for j in range(self.n):
            if i != j:
                aj = vs[j]
                self.equmap[i][j].setdefault(a, {}).setdefault(aj, 0)
                self.equmap[i][j][a][aj] += 1

    def equ_label(self, a, i):
        lab = self.get_label(a, i)
        self.equlabels[i][a] = lab
        return lab

    def value_identifier(self, vs, i, preferLabel):
        v = vs[i]
        useLabel = False
        valm, addrm = self.count_matches(vs, i)
        if addrm > valm:
            useLabel = True
        elif addrm == valm:
            useLabel = preferLabel

        if not self.isROM(v, i) and self.phase == 0:
            self.store_equ(vs, i)

        if useLabel:
            if self.isROM(v, i):
                return self.base_label(v, i)
            else:
                return self.equ_label(v, i)
        else:
            return f"0{v:04X}h"

    def f_wordlike(self, a, i, preferLabel):
        vs = []
        for j in range(self.n):
            aj = self.aconv(a, i, j)
            vs.append(little_endian(self.ds[j][aj+1:aj+3]))

        lab = self.value_identifier(vs, i, preferLabel)
        return [lab]

    def f_word(self, a, i):
        return self.f_wordlike(a, i, False)

    def f_jump(self, a, i):
        return self.f_wordlike(a, i, True)

    def f_offset(self, a, i):
        off = sig8(self.ds[i][a+1])
        v = a+2+off
        lab = self.base_label(v, i)
        return [lab]

    def f_byte_off(self, a, i):
        b = sig8(self.ds[i][a+1])
        s = "+" if b >= 0 else ""
        return [f"{s}{b}"]

    def f_byte_off_2(self, a, i):
        b = sig8(self.ds[i][a+1])
        s = "+" if b >= 0 else ""
        n = self.ds[i][a+2]
        return [f"{s}{b}", f"{n}"]

    def get_chunks(self, a, i, length):
        return [self.ds[j][a:a+length] for j, a in
                enumerate(self.aconvs(a, i))]

    def get_decodings(self, a, i):
        dec = []
        for j in range(self.n):
            dd = self.sk[j].disasm.get(self.aconv(a, i, j), None)
            if dd is None:
                dec.append(None)
            else:
                dec.append(dd.decoded)
        return dec

    def generate_labels(self):
        # first pass generates equmap, second pass generates equlabels
        for self.phase in range(2):
            for i in range(self.n):
                disasm = self.sk[i].disasm

                for d in disasm.values():
                    form = self.formatters[d.optype]
                    if form in [self.f_word, self.f_offset, self.f_jump]:
                        try:
                            form(d.oploc, i)
                        except IndexError:
                            continue

    def get_disasm(self, i, align, print_address=True):
        def put_aligns(a, out, currRow):
            if align:
                targetRow = self.row[self.align_repr(a, i)]
                for _ in range(targetRow-currRow):
                    out += "\n"
                currRow = targetRow
            return out, currRow

        out = ""
        disasm = self.sk[i].disasm
        anext = sorted(disasm.keys())[1:]+[len(self.ds[i])]
        currRow = 0

        for (a, d), an in zip(sorted(disasm.items()), anext):

            out, currRow = put_aligns(a, out, currRow)
            if a in self.labels[i].keys():
                out += f"{self.get_label(a, i)}:\n"
                currRow += 1
            chunks = self.get_chunks(a, i, an-a)
            try:
                args = self.formatters[d.optype](d.oploc, i)
                code = d.decoded.format(*args)
            except Exception as e:
                print(f"While decoding {self.fnames[i]} {a:04X}", d, "\n:", e)
                dth = ",".join([f"0{b:02X}h" for b in chunks[i]])
                code = f"defb {dth}"

            codeline = code.ljust(30)
            if print_address:
                al = self.get_address_repr(a, i)
            else:
                al = ""

            decs = self.get_decodings(a, i)
            if count_equalities(decs) > count_equalities(chunks):
                asdata = ""
            else:
                asdata = format_chunk(chunks[i])
            out += f"  {codeline} ; {al}  {asdata}\n"
            currRow += 1

        for (a, lab) in sorted(self.equlabels[i].items()):
            out, currRow = put_aligns(a, out, currRow)
            out += f"{lab}: equ 0{a:04X}h\n"
            currRow += 1
        return out

    def get_filename(self, i, suffix=None):
        stems = [Path(f).stem for f in self.fnames]
        if suffix is None:
            suffix = "_"+"_".join([stems[j] for j in range(self.n) if j != i])
        return stems[i]+suffix+".asm"


def main(filenames, suffix, pairwise, align):
    out = Path("cmpout")
    out.mkdir(exist_ok=True)

    if pairwise:
        n = len(filenames)
        for ai in range(n):
            for bi in range(ai+1, n):
                a = filenames[ai]
                b = filenames[bi]
                dis = Disassember([a, b])
                for i in range(dis.n):
                    open(out/dis.get_filename(i, suffix),
                         "w").write(dis.get_disasm(i, align))

    else:
        dis = Disassember(filenames)
        data = {"names": filenames, "similarity": dis.matchmatrix}
        with open(out/"similarity.json", "w") as f:
            json.dump(data, f, indent=2)

        for i in range(dis.n):
            open(out/dis.get_filename(i, suffix),
                 "w").write(dis.get_disasm(i, align))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Read the --suffix parameter.")

    parser.add_argument("filenames", nargs="+",
                        help="List of binaries to process.")
    parser.add_argument("--suffix", type=str, default=None,
                        help="Suffix to be used." +
                        "Defaults to stems of the other files the file is being compared to.")
    parser.add_argument("--pairwise", action="store_true",
                        help="Enable pairwise comparisons of binaries.")
    parser.add_argument("--align", action="store_true",
                        help="Align rows in the outputs so that matching code is located at the same line in the file.")

    args = parser.parse_args()
    main(args.filenames, args.suffix, args.pairwise, args.align)
