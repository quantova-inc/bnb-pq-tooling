#!/usr/bin/env python3
# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Independent alignment of the Quantova post quantum stack against the official
# NIST ACVP known answer vectors for signature verification.
#
# Source of the vectors: NIST ACVP-Server, FIPS 204 and FIPS 205 sigVer sets
#   https://github.com/usnistgov/ACVP-Server
# Each file holds the pure external interface known answers extracted as
#   expected pk message context signature   (expected 1 accept, 0 reject, dash is empty)
#
# Each case is verified with a stock OpenSSL 3.5 or newer that ships ML-DSA and
# SLH-DSA, with no Quantova code in the path, so agreement is across two
# independent implementations. The FIPS 204 and FIPS 205 external message
# 0x00 || len(ctx) || ctx || message is built here and checked with the internal
# interface (message-encoding:0) so any context value can be verified.
import subprocess, sys, tempfile, os, time

RAW = {"ML-DSA-65":1952, "ML-DSA-87":2592, "SLH-DSA-SHAKE-192s":48}
FILES = [
    ("cardano/acvp/ml-dsa-65-sigver.txt", "ML-DSA-65"),
    ("cardano/acvp/ml-dsa-87-sigver.txt", "ML-DSA-87"),
    ("cardano/acvp/slh-dsa-shake-192s-sigver.txt", "SLH-DSA-SHAKE-192s"),
]

def prefix(alg, rl):
    der = subprocess.run(["openssl","genpkey","-algorithm",alg,"-outform","DER"],capture_output=True).stdout
    pub = subprocess.run(["openssl","pkey","-inform","DER","-pubout","-outform","DER"],input=der,capture_output=True).stdout
    return pub[:len(pub)-rl]

def verify(pre, rawpk, mprime, sig):
    f=[]
    for b in (pre+rawpk, mprime, sig):
        t=tempfile.NamedTemporaryFile(delete=False); t.write(b); t.close(); f.append(t.name)
    r=subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",f[0],"-keyform","DER",
                      "-rawin","-in",f[1],"-sigfile",f[2],"-pkeyopt","message-encoding:0"],capture_output=True)
    for x in f: os.unlink(x)
    return r.returncode==0

def run(path, alg):
    base=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    pth=os.path.join(base, path) if not os.path.exists(path) else path
    pre=prefix(alg, RAW[alg]); ok=bad=n=0; t0=time.time()
    for line in open(pth):
        line=line.strip()
        if not line or line.startswith("#"): continue
        exp,pk,msg,ctx,sig=line.split()[:5]
        M=b"" if msg=="-" else bytes.fromhex(msg)
        C=b"" if ctx=="-" else bytes.fromhex(ctx)
        mprime=b"\x00"+bytes([len(C)])+C+M
        got=verify(pre, bytes.fromhex(pk), mprime, bytes.fromhex(sig))
        n+=1
        if got==(exp=="1"): ok+=1
        else: bad+=1; print(f"  MISMATCH {alg} expected {exp}")
    print(f"{alg}: {n} NIST ACVP cases, matched {ok}, mismatched {bad}, {1000*(time.time()-t0)/max(n,1):.1f} ms per case")
    return bad==0

if __name__=="__main__":
    allok=True
    for path,alg in FILES:
        allok &= run(path, alg)
    print("passed" if allok else "failed, see mismatches above")
    sys.exit(0 if allok else 1)
