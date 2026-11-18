#!/usr/bin/env python3
"""Independent re-implementation of HEDGE's H* and KDF in Python
(hashlib SHAKE256 + pyascon), cross-checked against the C library's
output from tools/kdf_vectors. Also checks the outer Ascon layer of a
Comb ciphertext with pyascon.

usage: kdf_vectors > v.json && python3 ref_check.py v.json path/to/pyascon
"""
import hashlib, json, sys
sys.path.insert(0, sys.argv[2])
import ascon  # pyascon (meichlseder/pyascon)

v = {k: bytes.fromhex(x) for k, x in json.load(open(sys.argv[1])).items()}

def field(b): return len(b).to_bytes(2, "big") + b

def hstar(x):
    return hashlib.shake_256(x).digest(32) + ascon.ascon_hash(x, "Ascon-Hash256", 32)

def kdf(ikm, label, ctx, L):
    lb = label.encode()
    x1 = hashlib.shake_256(field(lb) + field(ctx) + field(ikm)).digest(L)
    x2 = ascon.ascon_hash(field(ctx) + field(ikm), "Ascon-CXOF128", L, customization=lb)
    return bytes(a ^ b for a, b in zip(x1, x2))

checks = {
    "hstar":       hstar(v["x"]),
    "kdf_ms_32":   kdf(v["ikm"][:64], "ms", v["ctx"][:64], 32),
    "kdf_app_96":  kdf(v["ikm"][:32], "app", v["ctx"][:80], 96),
    "kdf_finD_16": kdf(v["ikm"][:32], "finD", v["ctx"][:64], 16),
}
ok = True
for k, ref in checks.items():
    same = ref == v[k]
    ok &= same
    print(f"  {k:12s} {'match' if same else 'MISMATCH'}")

# Outer layer of Comb is plain Ascon-AEAD128 over the inner ciphertext.
inner = ascon.ascon_decrypt(v["k_out"], v["n"], v["ctx"][:64], v["comb_ct"], "Ascon-AEAD128")
same = inner is not None and len(inner) == len(v["m"]) + 16
ok &= same
print(f"  {'comb_outer':12s} {'match' if same else 'MISMATCH'} (pyascon opens the outer Ascon layer)")
print("REFCHECK:", "all match" if ok else "MISMATCH")
sys.exit(0 if ok else 1)
