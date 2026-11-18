#!/usr/bin/env python3
"""Convert the X-Wing draft's spec/test-vectors.json into a C header."""
import json, sys
src, dst = sys.argv[1], sys.argv[2]
vs = json.load(open(src))
def arr(name, h):
    b = bytes.fromhex(h)
    body = ",".join(f"0x{x:02x}" for x in b)
    return f"static const uint8_t {name}[{len(b)}] = {{{body}}};\n"
out = ["/* Generated from draft-connolly-cfrg-xwing-kem spec/test-vectors.json. Do not edit. */\n",
       "#include <stdint.h>\n", f"#define XWING_NVEC {len(vs)}\n"]
for i, v in enumerate(vs):
    for f in ("seed", "eseed", "ss", "sk", "pk", "ct"):
        out.append(arr(f"xv{i}_{f}", v[f]))
out.append("static const uint8_t *const xv_seed[] = {" + ",".join(f"xv{i}_seed" for i in range(len(vs))) + "};\n")
for f in ("eseed", "ss", "sk", "pk", "ct"):
    out.append(f"static const uint8_t *const xv_{f}[] = {{" + ",".join(f"xv{i}_{f}" for i in range(len(vs))) + "};\n")
open(dst, "w").write("".join(out))
