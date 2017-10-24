# -*- coding: utf-8 -*-
"""
Created on Tue Oct 24 12:54:02 2017

@author: Leonardo
"""
from secp256k1 import G, order, prime, pointMultiply, pointAdd
from secp256k1 import a as asecp256k1
from secp256k1 import b as bsecp256k1
from FiniteFields import modular_sqrt

def ECpoint2compressedStr(P):
    return ("02" if P[1]%2==0 else "03") + hex(P[0])[2:].zfill(64)

def str2ECpoint(Pstr):
    assert Pstr[:2] in ("02","03","04")
    assert len(Pstr) in (66,130)
    if Pstr[:2] == "04":
        return int(Pstr[2:66], 16), int(Pstr[66:], 16)
    else:
        x = int(Pstr[2:66], 16)
        y = modular_sqrt(x**3 + asecp256k1*x + bsecp256k1, prime)
        if Pstr[:2] == "03":
            return x, (-y % prime) if (y % 2 == 0) else y
        else: #"02"
            return x, y if (y % 2 == 0) else (-y % prime)

# verification sign to contract
print("\n   *** Verification of a sign-to-contract commitment ***")

# Receipt for verification
txid = 0xf16dd2eee2254a47690fb56c112590233f76e9c6b0ac80d6911b7a34ef0d81dd
ind = 0
msg = "test1 23oct2017 leonardo comandini"
Rstr = "037e44cc4dce2e6249d9dca156d538b9c02f0703dab0b4294954152c98e78fb9b0"
print("\nReceipt of the commitment:")
print("  - txid :", hex(txid)[2:])
print("  - ind  :", ind,       "(the first is (0))")
print("  - msg  :", msg)
print("  - R    :", Rstr)

print("\n1. Go on a blockchain explorer and extract the raw tx corresponding to the above txid:")
# with blockchain info to get the raw tx add "?format=hex"
# https://blockchain.info/tx/f16dd2eee2254a47690fb56c112590233f76e9c6b0ac80d6911b7a34ef0d81dd?format=hex
rawTx = "01000000012b8aa127de3d63887c78d5d7794fd404835bfb2ea867924fff1d651984739d21000000006b4830450221008d0fbae78e97e3776437f66d708f7b88c8b0549cf7a56e6e0cb82f01d94bd57b02206002fcd0f3a10920774f0b0518701f891874587cd0be7261b9f3d7860a103bb00121039697e867ae7c317d60e3b5e1cc9d35cadb1178c422e567ec4aee82c6f46a06f3ffffffff0110980200000000001976a914030c8a43b75b3109875c94139b2b95734090737888ac00000000"
print(rawTx)
print("\n2. Look at the ", ind+1, "° input (could be done better, now is done manually)", sep = "")
# extract the eph public key
x_W = rawTx[96:96+64] if int(rawTx[92:94],16) == 0x21 else rawTx[94:94+64]
print("\n3. Extract from the raw tx the x coord of the eph pub key:")
print(x_W)
print("\n4. Compute e = hash(msg||R):")
print("(see code for details, in this case a suboptimal hash was used (sigh!))")
e = hash(msg + Rstr) % order
print(e)
print("\n5. Compute W = eG + R:")
R = str2ECpoint(Rstr)
temp = pointMultiply(e, G)
Wrecomputed = pointAdd(R, temp)
print("04")
print(hex(Wrecomputed[0])[2:])
print(hex(Wrecomputed[1])[2:])
print("\n6. Check that the x coord of the recomputed W is equal to the one seen on the blockchain")
assert x_W == hex(Wrecomputed[0])[2:]
print("\n   *** Verified! *** ")

print("\nThis proves the commitment, in fact committing ex-post is not feasible ")
print("because the map R -> h(msg||R)G + R is not computationally invertible")