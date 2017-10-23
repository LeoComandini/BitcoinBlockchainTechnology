# -*- coding: utf-8 -*-
"""
Created on Mon Oct 23 11:05:19 2017

@author: Leonardo
"""

from hashlib import sha256
from secp256k1 import order, G, pointMultiply, pointAdd

# sources of the idea:
# (sipa, alternative to OP_RETURN)
# https://bitcoin.stackexchange.com/questions/37206/alternatives-to-op-return-to-store-data-in-bitcoin-blockchain
# (poelstra, issue on opentimestamps)
# https://github.com/opentimestamps/python-opentimestamps/issues/12

# IDEA: given a message 'msg' to commit
#       every time a EC point 'P' is used 
#       you can commit msg to 
#       G = e*G + P, with e = hash(P||msg)
#       (by revealing P and msg you prove the commit)

print("\n*** Let's suppose we are using an EC point for a given (and possibly unknown) purpose. ")
print("*** We can commit a message into that point with 0 overhead cost while it is still  ")
print("*** serving that purpose.")

print("\n*** Message to commit")
msg = "Hello World!"
print("    msg:", msg)

print("\n*** Start from a couple private and public key (x,P)")
x = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
# 0 < privKey < order
assert 0 < x        , "Invalid Private Key"
assert     x < order, "Invalid Private Key"
#print("\n*** EC Private Key x:")
print("      x:", hex(x))

PubKey = pointMultiply(x, G)
#print("*** EC Public Key (uncompressed) P:")
print("      P: 04")
print("        ", hex(PubKey[0]))
print("        ", hex(PubKey[1]))

# e = hash(P||msg)
# REM: exactly this concatenation must be used also in the verification
temp = hex(PubKey[0]) + hex(PubKey[1]) + msg
e = int(sha256(temp.encode()).hexdigest(),16)
print("\n*** Shifting (or committing) parameter e = hash(P||msg)")
print("      e:", hex(e))

Q = pointAdd(pointMultiply(e, G), PubKey)
print("*** Shifted (or committed) EC point (uncompressed) Q = eG + P")
print("      Q: 04")
print("        ", hex(Q[0]))
print("        ", hex(Q[1]))

print("\n*** Q should be written on something considered immutable (e.g. the Bitcoin blockchain)")
print("*** (x + e) is the corresponding private key")
print("*** P and msg (and hence e) are possibly public")

print("\n*** A receipt of the commitment must contain:")
print("***   1. Where to find Q")
print("***   2. How to compute e")
print("***   3. P")
print("***   4. msg")

print("\n*** To prove the commitment of msg the committer must:")
print("***    1. Reveal msg and P")
print("***    2. Compute e")
print("***    3. Show that Q = eG + P")
print("*** However this does not compromise x, thus (x + e) is still secret and ")
print("*** Q serves its purpose as in the case with no commitment.")

print("\n--------------------------------")
print("A possible Use Case:")
k = 0x35C13A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725 
R = pointMultiply(k, G)
msg2 = "Hi, I am Leo"
temp = hex(R[0]) + hex(R[1]) + msg2
e = int(sha256(temp.encode()).hexdigest(), 16)
temp = pointMultiply(e, G)
W = pointAdd(temp, R)

print("\nLet's pretend that you see on the blockchain this x coord (x_W) of the eph pub key W")
print("   x_W:", hex(W[0]))
print("\nI want to prove you that I committed a message in it")
print("The message I committed is:   -", msg2, "-")
print("In order to prove my commitment, I tell you that W = eG + R, where e = hash(R||msg)")
print("     R: 04")
print("       ", hex(R[0]))
print("       ", hex(R[1]))
print("     e:", hex(e))
print("eG + R: 04")
print("       ", hex(W[0]))
print("       ", hex(W[1]))
print("You can check the x coord of (eG + R) and W are the same,")
print("it is not feasible to obtain that result without commitment")
print("since the map P -> h(P||msg)G + P is not invertible")

# How to use ECCommitment in a bitcoin tx?
# in a P2PKH tx there are 2 EC points:
#   - (pay-to-contract) the public key
#   - (sign-to-contract) half of the singature, i.e. the ephemeral public key