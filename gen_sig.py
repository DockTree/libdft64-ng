#!/usr/bin/env python3
"""
Generate fallback signature metadata for libTF.

    python3 gen_sig.py -o tf_sig.inc stdlib.h unistd.h ...
"""
import argparse, re, json, clang.cindex as cc

# ================  helpers  ==================================================
PTR  = {cc.TypeKind.POINTER, cc.TypeKind.INCOMPLETEARRAY, cc.TypeKind.LVALUEREFERENCE}
SIZE = {cc.TypeKind.UINT, cc.TypeKind.ULONG, cc.TypeKind.ULONGLONG,
        cc.TypeKind.INT,  cc.TypeKind.LONG,  cc.TypeKind.LONGLONG}

def is_pointer(t):   return t.kind in PTR
def is_size_t(t):    return t.get_canonical().kind in SIZE or t.spelling=="size_t"

def looks_out_param(arg):
    """pointer to void/char/struct  OR   non-const pointer"""
    pt = arg.type.get_pointee()
    return (pt.kind in (cc.TypeKind.RECORD, cc.TypeKind.CHAR_S, cc.TypeKind.VOID)
            or not arg.type.is_const_qualified())

# some API families return bytes-written, treat that as the length.
RETVAL_LEN = re.compile(r"^(read|recv|fread|getline|recvfrom|pread)")

# ================  main logic  ===============================================
def extract_sig(fn):
    name, args = fn.spelling, list(fn.get_arguments())
    nargs      = len(args)
    if nargs==0 and not is_pointer(fn.result_type):
        return None

    in_mask, out_mask, len_map = 0, 0, [-1]*nargs

    # pass 1 – classify
    for i, a in enumerate(args):
        if is_pointer(a.type):
            if looks_out_param(a): out_mask |= 1<<i
            else:                  in_mask  |= 1<<i

    # pass 2 – (ptr,len) pairing  (ptr then size_t)
    for i in range(nargs-1):
        if out_mask & (1<<i) and is_size_t(args[i+1].type):
            len_map[i] = i+1

    # pass 3 – special: size comes from retval
    if RETVAL_LEN.match(name):
        for i in range(nargs):
            if out_mask & (1<<i) and len_map[i]==-1:
                len_map[i] = -2             # -2 means “size = retval”

    # pass 4 – IO flags
    flags = []
    if out_mask or is_pointer(fn.result_type): flags.append("IO_SRC")
    if in_mask:                                flags.append("IO_SINK")
    if not flags: return None

    return {
        "name"    : name,
        "flags"   : "|".join(flags),
        "nargs"   : nargs,
        "len_map" : len_map + [-1]*(6-nargs),   # pad to 6
    }

# ================  driver  ====================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", required=True, help="output .inc file")
    ap.add_argument("--json", help="also emit JSON table")
    ap.add_argument("headers", nargs="+")
    ap.add_argument("-I", "--include", action="append", default=[])
    ap.add_argument("-D", "--define",  action="append", default=[])
    args = ap.parse_args()

    cc.Config.set_library_file("libclang.so")      # adjust if needed
    clang_args = [f"-I{p}" for p in args.include] + [f"-D{d}" for d in args.define]

    entries = []
    for hdr in args.headers:
        tu = cc.Index.create().parse(hdr, args=clang_args)
        for c in tu.cursor.get_children():
            if c.kind is cc.CursorKind.FUNCTION_DECL and not c.is_definition():
                sig = extract_sig(c)
                if sig: entries.append(sig)

    # stable order for diff-friendliness
    entries.sort(key=lambda e: e["name"])

    # emit .inc (X-macro style)
    with open(args.out, "w") as f:
        f.write("// Auto-generated, DO NOT EDIT.\n")
        for e in entries:
            lm = ", ".join(map(str, e["len_map"]))          #  -1, 2, -1, …
            f.write(f'TF_SIG_ENTRY("{e["name"]}", {e["flags"]}, {e["nargs"]}, {lm})\n')

    # optional JSON for tooling
    if args.json:
        with open(args.json, "w") as jf:
            json.dump(entries, jf, indent=1, sort_keys=True)

if __name__ == "__main__":
    main()
