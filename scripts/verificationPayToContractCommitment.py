# -*- coding: utf-8 -*-
"""
Created on Thu Oct 19 16:45:41 2017

@author: Leonardo
"""
# first proposed by Pieter Wuille on 3 Mar 2015 (maybe before?)
# https://bitcoin.stackexchange.com/questions/37206/alternatives-to-op-return-to-store-data-in-bitcoin-blockchain
import hashlib
import base58
import secp256k1
import FiniteFields

# should write a file with the functions for changing formats 
# and performing the commitment

# data for verification
msg = "test2 19oct2017 leonardo comandini"
txid = "219d738419651dff4f9267a82efb5b8304d44f79d7d5787c88633dde27a18a2b"
addressWif = "1P15vtUfm38zKRJhPSjLm51JRcunNp4q4i"
PStr = "02d7084dea1dbf27d40f801309c93253382f2e0ef35f502b1dd6aa13ba2694b92d"

print("*** Pay-to-contract verification ***")
print("*** (a first test) ")
print("\n*** I state that on 19 oct 2017 I committed to this message:")
print("   ",msg)
print("\n*** Proof of my commitment ")
print("*** 1. Go to your favourite block explorer and look for the transaction with txid:")
print("      ",txid)
print("*** 2. You can check that the first output is referred to address (WIF):")
print("      ",addressWif)
print("*** 3. To prove my commitment I need to reveal you P (point on EC curve):")
print("      ",PStr[:2])
print("      ",PStr[2:])
print("*** 4. Compute the public key Q = hash(P||msg)G + P")
print("***    (see the code for precise details)")
# substitute with 
#    PPoint = pubKeyStr2Point(PStr)
yOdd = int(PStr[:2], 16) % 2
xP = int(PStr[2:], 16)
temp = (xP**3 + secp256k1.a*xP + secp256k1.b) % secp256k1.prime
yP = FiniteFields.modular_sqrt(temp, secp256k1.prime)
if yP % 2 == 0: #could be done smarter!!
    if PStr[:2] == "03":
        yP = (-yP) % secp256k1.prime 
else:
    if PStr[:2] == "02":
        yP = (-yP) % secp256k1.prime 
PPoint = (xP,yP)
# substitute with 
#    QPoint = secp256k1(msg,PPoint)
#    QStr = pubKeyPoint2Str(QPoint) # or print with an ad hoc function
#    addressQWif = pubkey2addressWif(QPoint)
temp = PStr + msg 
e = int(hashlib.sha256(temp.encode()).hexdigest(),16) % secp256k1.order
temp = secp256k1.pointMultiply(e,secp256k1.G)
QPoint = secp256k1.pointAdd(temp,PPoint)
yOdd = QPoint[1] % 2 
QStr =  ("03" if yOdd else "02") + hex(QPoint[0])[2:] # avoid to store 0x for coherence with above
temp = (b'\x03' if yOdd else b'\x02') + QPoint[0].to_bytes(32, byteorder='big')
h1 = hashlib.sha256(temp).digest()
h2 = hashlib.new('ripemd160', h1).digest()
vh160 = b'\x00' + h2
addressQWif = base58.b58encode_check(vh160)

print("      ",QStr[:2])
print("      ",QStr[2:])
print("*** 5. Compute the address (WIF) corresponding to Q")
print("      ",addressQWif)
print("*** 6. Check that the address you just computed is equal to one seen on the blockchain")
if addressWif == addressQWif: 
    print("***    --- Verified! --- ")
else:
    print("***    --- Not verified --- ")

print("\n\n*** Why the commmitment is valid?")
print("*** The maps  P -> hash(P||msg)G + P  ")
print("***           Q -> HASH160            are not invertible,")
print("*** hence the commitment to msg could not be done ex-post")
