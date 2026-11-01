#!/usr/bin/env python3
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json, sys, subprocess, tempfile, os, urllib.request

SOURCES = [
    "https://raw.githubusercontent.com/cardano-foundation/CIPs/master/CIP-0206/test-vectors.json",
    "https://raw.githubusercontent.com/quantova-inc/CIPs/cip-post-quantum-signature-builtins/CIP-0206/test-vectors.json",
]
SCHEME = {1: "ML-DSA-44", 2: "ML-DSA-65", 3: "ML-DSA-87", 4: "SLH-DSA-SHA2-128s"}
RAWPK = {1: 1312, 2: 1952, 3: 2592, 4: 32}
RAWSIG = {1: 2420, 2: 3309, 3: 4627, 4: 7856}

def load():
    if len(sys.argv) > 1:
        return json.load(open(sys.argv[1]))
    if os.path.exists("test-vectors.json"):
        return json.load(open("test-vectors.json"))
    for url in SOURCES:
        try:
            return json.load(urllib.request.urlopen(url))
        except Exception:
            continue
    raise SystemExit("could not load test-vectors.json, pass a path as the first argument")

def hdr(b):
    ver = b[0] if len(b) >= 1 else None
    algId = int.from_bytes(b[1:3], "big") if len(b) >= 3 else None
    kind = b[3] if len(b) >= 4 else None
    body = b[4:]
    return ver, algId, kind, body

def spki_prefix(scheme, rawlen, tmp):
    k = os.path.join(tmp, "k.pem"); p = os.path.join(tmp, "p.der")
    subprocess.run(["openssl", "genpkey", "-algorithm", scheme, "-out", k], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", k, "-pubout", "-outform", "DER", "-out", p], check=True, capture_output=True)
    der = open(p, "rb").read()
    return der[:len(der) - rawlen]

def main():
    d = load()
    tmp = tempfile.mkdtemp()
    prefixes = {}
    def prefix(algId):
        if algId not in prefixes:
            prefixes[algId] = spki_prefix(SCHEME[algId], RAWPK[algId], tmp)
        return prefixes[algId]
    ok = bad = 0

    print("Encoding")
    for v in d["encoding"]:
        ver, algId, kind, body = hdr(bytes.fromhex(v["object"]))
        want = RAWPK[algId] if kind == 1 else RAWSIG[algId]
        good = ver == 1 and algId == v["algId"] and kind == v["kind"] and len(body) == v["bodyLength"] == want
        ok += good; bad += not good
        print(("  ok   " if good else "  FAIL ") + v["scheme"] + (" public key" if kind == 1 else " signature"))

    print("Verification")
    for v in d["verification"]:
        exp = v["expected"]
        vpk, apk, kpk, rpk = hdr(bytes.fromhex(v["publicKey"]))
        vsg, asg, ksg, rsg = hdr(bytes.fromhex(v["signature"]))
        if exp == "failure":
            expects_ml = v.get("builtin") == "verifyMlDsaSignature"
            family_mismatch = (expects_ml and apk not in (1, 2, 3)) or (not expects_ml and apk != 4)
            good = apk != asg or kpk != 1 or ksg != 2 or apk not in SCHEME or family_mismatch
            ok += good; bad += not good
            print(("  ok   " if good else "  FAIL ") + "evaluation fails, " + v["description"][:52])
            continue
        open(os.path.join(tmp, "pk.der"), "wb").write(prefix(apk) + rpk)
        open(os.path.join(tmp, "m.bin"), "wb").write(bytes.fromhex(v["message"]))
        open(os.path.join(tmp, "s.bin"), "wb").write(rsg)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                            "-inkey", os.path.join(tmp, "pk.der"), "-rawin",
                            "-in", os.path.join(tmp, "m.bin"), "-sigfile", os.path.join(tmp, "s.bin")],
                           capture_output=True)
        verified = r.returncode == 0
        good = verified == (exp is True)
        ok += good; bad += not good
        print(("  ok   " if good else "  FAIL ") + ("verifies, " if exp is True else "rejected, ") + v["description"][:52])

    print("Rejection")
    for v in d["rejection"]:
        b = bytes.fromhex(v["object"])
        ver, algId, kind, body = hdr(b)
        if kind in (1, 2) and algId in SCHEME:
            want = RAWPK[algId] if kind == 1 else RAWSIG[algId]
            lenbad = len(body) != want
        else:
            lenbad = True
        malformed = ver != 1 or algId not in SCHEME or algId == 0 or kind not in (1, 2) or len(b) < 4 or lenbad
        ok += malformed; bad += not malformed
        print(("  ok   " if malformed else "  FAIL ") + "refused, " + v["description"][:52])

    print()
    print("passed " + str(ok) + " failed " + str(bad))
    sys.exit(1 if bad else 0)

main()
