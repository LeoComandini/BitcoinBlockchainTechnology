# -*- coding: utf-8 -*-
"""
Created on Mon Oct 23 15:20:27 2017

@author: Leonardo
"""
from binascii import unhexlify
from hashlib import sha256
from os import urandom
from secp256k1 import G, order, pointMultiply, pointAdd
from FiniteFields import modInv

# build the sign-to-contract tx

def hexStr2int(a):
    """ IN: hex str in little endian --> OUT: int
    """
    return int(unhexlify(a)[::-1].hex(), 16)

def int2hexStr(a, nbytes):
    return a.to_bytes(nbytes, byteorder = 'little').hex()

def dsha256(inp):
    return sha256(sha256(inp).digest()).digest().hex()

def ECpoint2compressedStr(P):
    return ("02" if P[1]%2==0 else "03") + hex(P[0])[2:].zfill(64)

def signAndCommit(privKey,h,msg,k = None):
    if k == None:
        k = int.from_bytes(urandom(32), byteorder='big')
    R = pointMultiply(k, G)
    e = hash(msg + ECpoint2compressedStr(R)) % order
    temp = pointMultiply(e, G)
    W = pointAdd(R, temp)
    h = int(h, 16)
    z = ((h + R[0] * privKey) * modInv(k + e, order)) % order
    return (W[0], z), R

# Data to redeem the tx output locked

# Data of the receiver

# from https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx?noredirect=1&lq=1
# follow the steps indicated to create the tx

# 1.
version = int2hexStr(1,4) # 1
# 2.
numInput = int2hexStr(1,1) # 1
# 3. tx id of the previous tx
outpointId = "219d738419651dff4f9267a82efb5b8304d44f79d7d5787c88633dde27a18a2b"
# 4. index of the previous tx
outpointIndex = int2hexStr(1,4) # 1
# 6.
outputScriptToRedeem = "76a914f156e1c0941d3e5b829e633d609fb52601b3350e88ac"
# 5.
lenOutputScriptToRedeem = hex(len(outputScriptToRedeem)//2)[2:]
# 7.
sequenceNumber = int2hexStr(2**32-1,4) 
# 8.
numOutput = int2hexStr(1,1) # 1 
# 9.
amountPrevStr = "400d030000000000"
amountPrev = hexStr2int(amountPrevStr)
fee = 20000
amount = amountPrev - fee
assert amount > 0
assert amount < amountPrev
amountStr = int2hexStr(amount, 8)
# 11.
address = "097072524438d003d23a2f23edb65aae1bb3e469" # TEMPPPPP
outputScript = "76a914" + address + "88ac"
# 10.
lenOutputScript = hex(len(outputScript)//2)[2:]
# 12. 
nlocktime = int2hexStr(0,4) # 0
# 13. sig hash type
sigHashType = int2hexStr(1,4) # 1
# 14. compute h
txForHashStr = version + numInput + outpointId + outpointIndex + \
               lenOutputScriptToRedeem + outputScriptToRedeem + sequenceNumber + \
               numOutput + amountStr + lenOutputScript + outputScript + \
               nlocktime + sigHashType
txForHashBytes = int(txForHashStr, 16).to_bytes(len(txForHashStr)//2, byteorder='big')
h = dsha256(txForHashBytes)
# 15. signing
privKey = 1 # temp # corresponding to the pubKey of outputScriptToRedeem
msg = "test1 23oct2017 leonardo comandini"
(x_W, z), R = signAndCommit(privKey,h,msg,k = None)
# DER encoding
DERfollows = '30'
x_WDER = ("00" if x_W > 2**(256-1)-1 else "") + hex(x_W)[2:].zfill(64)
zDER   = ("00" if z   > 2**(256-1)-1 else "") + hex(  z)[2:].zfill(64)
x_WDER = "02" + hex(len(x_WDER)//2)[2:].zfill(2) + x_WDER
zDER   = "02" + hex(len(  zDER)//2)[2:].zfill(2) +   zDER
lenSig = hex(len(x_WDER + zDER)//2)[2:].zfill(2) 
hashCodeType = int2hexStr(1,1)
pubKey = (1,1) #temp # pubkey of the script to redeem
pubKeyStr = ECpoint2compressedStr(pubKey)
lenPubKeyStr = hex(len(pubKeyStr)//2)[2:].zfill(2)
DERsig = DERfollows + lenSig + x_WDER + zDER + hashCodeType + lenPubKeyStr + pubKeyStr
# 16. concatenate
lenSigPK = hex(len(DERsig)//2 + 1)[2:].zfill(2)
DERsig = lenSigPK + DERsig
# 17. We then replace the one-byte, varint length-field from step 5 with the  
#     length of the data from step 16. The length is 106 bytes, or 0x6a bytes: 6a

# 18. And we replace the temporary scriptSig from Step 6 with the data  
#     structure constructed in step 16.

# 19. We finish off by removing the four-byte hash code type we added in  
#     step 13, and we end up with the following stream of bytes, which is the final transaction:
finalTx = version + numInput + outpointId + outpointIndex + \
          DERsig + sequenceNumber + numOutput + amountStr + \
          lenOutputScript + outputScript + nlocktime

#01000000
#01
#219d738419651dff4f9267a82efb5b8304d44f79d7d5787c88633dde27a18a2b
#01000000
#6b
#30
#45
#02
#20
#2ce6256f8f32d140ee020fcf40fae5edf3edacb7a50193ffab2992812592c9d4
#02
#21
#00b28c7e7bf1f0562ba0e9f2d1f4b90deca38a977b82c2490c8894320682599d0b
#01
#21
#03
#0000000000000000000000000000000000000000000000000000000000000001
#ffffffff
#0120bf020000000000
#1976a914097072524438d003d23a2f23edb65aae1bb3e46988ac
#00000000




    