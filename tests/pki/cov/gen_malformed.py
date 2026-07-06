#!/usr/bin/env python3
# Build malformed X.509 DER certs for wn_x509 coverage by editing a DER tree and
# re-serializing (all parent lengths recomputed). Output -> tests/pki/cov/.
import sys, os

def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

class Node:
    def __init__(self, tag, value=None, children=None):
        self.tag = tag
        self.value = value          # bytes for primitive
        self.children = children    # list[Node] for constructed
    def constructed(self):
        return self.children is not None
    def body(self):
        if self.constructed():
            return b''.join(c.serialize() for c in self.children)
        return self.value
    def serialize(self):
        b = self.body()
        return bytes([self.tag]) + enc_len(len(b)) + b

def parse1(b, i=0):
    start = i
    tag = b[i]; i += 1
    l = b[i]; i += 1
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(b[i:i+n], 'big'); i += n
    body = b[i:i+l]; i += l
    if tag & 0x20:
        kids = []; j = 0
        while j < len(body):
            c, adv = parse1(body, j); kids.append(c); j += adv
        return Node(tag, children=kids), i - start
    return Node(tag, value=body), i - start

BASE = 'tests/pki/cov/feat_ecc.der'
OUT = 'tests/pki/cov'

def load():
    return parse1(open(BASE, 'rb').read())[0]

def find_ext(tbs_exts_seq, oid_last):
    # extensions SEQ -> [Extension SEQ{ OID, [crit], OCTET }]
    for ext in tbs_exts_seq.children:
        oid = ext.children[0]
        if len(oid.value) == 3 and oid.value[0] == 0x55 and oid.value[1] == 0x1d and oid.value[2] == oid_last:
            return ext
    return None

def tbs_and_exts(cert):
    tbs = cert.children[0]
    # extensions is the [3] wrapper -> SEQ
    for c in tbs.children:
        if c.tag == 0xA3:
            return tbs, c.children[0]
    return tbs, None

def octet_of(ext):
    for c in ext.children:
        if c.tag == 0x04:
            return c
    return None

def write(name, cert):
    p = os.path.join(OUT, name)
    open(p, 'wb').write(cert.serialize())
    print('wrote', p, len(cert.serialize()), 'bytes')

# --- empty EKU extnValue (SEQUENCE of 0 KeyPurposeIds) ---
cert = load(); tbs, exts = tbs_and_exts(cert)
ext = find_ext(exts, 0x25)          # EKU 2.5.29.37
octet_of(ext).value = bytes([0x30, 0x00])   # OCTET wraps empty SEQUENCE
write('mal_empty_eku.der', cert)

# --- empty SAN extnValue ---
cert = load(); tbs, exts = tbs_and_exts(cert)
ext = find_ext(exts, 0x11)          # SAN 2.5.29.17
octet_of(ext).value = bytes([0x30, 0x00])
write('mal_empty_san.der', cert)

# --- empty extensions SEQUENCE ---
cert = load(); tbs, exts = tbs_and_exts(cert)
exts.children = []
write('mal_empty_exts.der', cert)

# --- duplicate SAN (append a copy of the SAN Extension) ---
cert = load(); tbs, exts = tbs_and_exts(cert)
san = find_ext(exts, 0x11)
import copy
exts.children.append(copy.deepcopy(san))
write('mal_dup_san.der', cert)

# --- basicConstraints SEQUENCE{ cA, pathLen, <extra> } : trailing after pathLen ---
cert = load(); tbs, exts = tbs_and_exts(cert)
bc = find_ext(exts, 0x13)
# SEQUENCE len 7: BOOLEAN cA=TRUE, INTEGER pathLen=0, then a stray byte
octet_of(bc).value = bytes([0x30,0x07, 0x01,0x01,0xFF, 0x02,0x01,0x00, 0x00])
write('mal_bc_trailing.der', cert)

def child_seqs(tbs):
    return [i for i, c in enumerate(tbs.children)]

def sigalg_and_spki(cert):
    tbs = cert.children[0]
    a3 = [i for i, c in enumerate(tbs.children) if c.tag == 0xA3][0]
    # tbs: [version[0], serial, sigAlg, issuer, validity, subject, SPKI, [3]]
    return cert.children[1], tbs.children[2], tbs.children[a3 - 1]  # outerSig, innerSig, spki

# --- ECDSA signatureAlgorithm with a trailing NULL (noParams alg must have none) ---
cert = load()
outer_sig, inner_sig, _ = sigalg_and_spki(cert)
outer_sig.children.append(Node(0x05, value=b''))   # append NULL to both so inner==outer
inner_sig.children.append(Node(0x05, value=b''))
write('mal_sigalg_trailing.der', cert)

# --- subjectUniqueID present (context [2] IMPLICIT BIT STRING) before extensions ---
cert = load()
tbs = cert.children[0]
a3 = [i for i, c in enumerate(tbs.children) if c.tag == 0xA3][0]
tbs.children.insert(a3, Node(0x82, value=b'\x00\xff'))   # [2] uniqueID: 0 unused bits + data
write('mal_uniqueid.der', cert)

# --- Ed25519 SPKI AlgorithmIdentifier carrying parameters (Ed takes none) ---
edc = parse1(open('tests/pki/server/ed-cert.der', 'rb').read())[0]
etbs = edc.children[0]
ea3 = [i for i, c in enumerate(etbs.children) if c.tag == 0xA3]
espki = etbs.children[(ea3[0] - 1) if ea3 else -1]
espki.children[0].children.append(Node(0x05, value=b''))  # NULL param in algid
open('tests/pki/cov/mal_ed_params.der', 'wb').write(edc.serialize())
print('wrote tests/pki/cov/mal_ed_params.der', len(edc.serialize()), 'bytes')

# --- RSA modulus far larger than the math backend supports: RsaRawNE accepts a
#     positive INTEGER, but wc_RsaPublicKeyDecodeRaw rejects the oversized value ---
rc = parse1(open('tests/pki/server/rsa-cert.der', 'rb').read())[0]
rtbs = rc.children[0]
ra3 = [i for i, c in enumerate(rtbs.children) if c.tag == 0xA3]
rspki = rtbs.children[(ra3[0] - 1) if ra3 else -1]
bitstr = rspki.children[1]                 # subjectPublicKey BIT STRING
inner = bitstr.value                       # 0x00 unused-bits + RSAPublicKey DER
rsapub = parse1(inner, 1)[0]               # RSAPublicKey SEQ{ modulus, exponent }
rsapub.children[0].value = b'\x7f' + b'\xff' * 1599   # ~12800-bit positive modulus
bitstr.value = inner[:1] + rsapub.serialize()
open('tests/pki/cov/mal_rsa_badkey.der', 'wb').write(rc.serialize())
print('wrote tests/pki/cov/mal_rsa_badkey.der', len(rc.serialize()), 'bytes')

# --- notBefore UTCTime of wrong length (12) : neither UTCTime(13) nor GenTime(15) ---
tc = parse1(open('tests/pki/server/ec-cert.der', 'rb').read())[0]
ttbs = tc.children[0]
for c in ttbs.children:
    if c.tag == 0x30 and c.children and c.children[0].tag in (0x17, 0x18):
        c.children[0].value = b'250101000000'   # 12 bytes, no 'Z'
        break
open('tests/pki/cov/mal_time_badlen.der', 'wb').write(tc.serialize())
print('wrote tests/pki/cov/mal_time_badlen.der', len(tc.serialize()), 'bytes')
