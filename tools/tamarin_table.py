#!/usr/bin/env python3
"""Turn tamarin/results_hedge.txt into the LaTeX rows of the paper's Tamarin table.
usage: tamarin_table.py results_hedge.txt > rows.tex"""
import re, sys

NAMES = [
    ("executable", "L1 Executability"),
    ("session_key_secrecy_device", "L2 Session-key secrecy, FS, PSK fallback (device)"),
    ("session_key_secrecy_gateway", "L2$'$ Same, gateway view"),
    ("agreement_gateway_to_device", "L3 Injective agreement $\\gw\\to\\dev$"),
    ("agreement_device_to_gateway", "L4 Injective agreement $\\dev\\to\\gw$"),
    ("identity_secrecy_hedged", "L5 Identity privacy, hedged"),
    ("app_outer_key_secrecy", "H1 Outer app.\\ key secret unless Ascon broken"),
    ("app_inner_key_secrecy", "H2 Inner app.\\ key secret unless Romulus broken"),
    ("record_secrecy_hedged", "L6 Record confidentiality, one AEAD break"),
    ("record_integrity_outer", "L7a Record integrity while Ascon intact"),
    ("record_integrity_inner", "L7b Record integrity while Romulus intact"),
    ("record_integrity_hedged", "L7 Record integrity, one AEAD break"),
    ("sanity_fs_attack_exists", "S1 Key learned if both KEMs broken (expect trace)"),
    ("sanity_identity_needs_one_aead", "S2 Identity, both AEADs broken (expect attack)"),
    ("sanity_record_needs_one_aead", "S3 Records, both AEADs broken (expect attack)"),
]
res = {}
for line in open(sys.argv[1]):
    m = re.match(r"\s+(\w+)(?: \([\w-]+\))?: (.*?)\s+\[wall (\d+)s\]", line)
    if m:
        res[m.group(1)] = (m.group(2), int(m.group(3)))
rows = []
for key, label in NAMES:
    if key not in res:
        rows.append(f"{label} & \\pending{{not run}} & -- \\\\")
        continue
    r, t = res[key]
    m = re.search(r"(verified|falsified)[^(]*\((\d+) steps\)", r)
    if m:
        word = "verified" if m.group(1) == "verified" else "attack found"
        if key == "sanity_fs_attack_exists" and m.group(1) == "verified":
            word = "attack found"   # exists-trace lemma: verified = the attack trace exists
        r = f"{word} ({m.group(2)})"
    else:
        r = "\\pending{" + r.strip(": ") + "}"
    tt = f"{t}\\,s" if t < 120 else f"{t/60:.1f}\\,min"
    rows.append(f"{label} & {r} & {tt} \\\\")
print("\n".join(rows))
