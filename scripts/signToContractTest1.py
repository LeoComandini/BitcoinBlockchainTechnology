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
from base58 import b58decode_check

# build the sign-to-contract tx

print("!!! This code doesn't provide a valid tx unless you know \n!!! and write the correct privKey")

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
    assert msg != None
    e = hash(msg + ECpoint2compressedStr(R)) % order # error, used a stupid hash function :(
    temp = pointMultiply(e, G)
    W = pointAdd(R, temp)
    h = int(h, 16)
    z = ((h + W[0] * privKey) * modInv(k + e, order)) % order
    return (W[0], z), R

def txRawStr2txId(txRawStr):
    txRawBytes = int(txRawStr, 16).to_bytes(len(txRawStr)//2, byteorder='big')
    return sha256(sha256(txRawBytes).digest()).digest()[::-1].hex()

# Data to redeem the tx output locked
#  - outpointId (3.)
#  - outpointIndex (4.)
#  - amountPrevStr (9.) (to decide fee and new output amount)
#
# Data of the receiver
#  - address in hex (11.)
#
# Commitment data:
#  - msg (15.)

# from https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx?noredirect=1&lq=1
# follow the steps indicated to create the tx

# 1.
version = int2hexStr(1,4) # 1
# 2.
numInput = int2hexStr(1,1) # 1
# 3. tx id of the previous tx
outpointId = "219d738419651dff4f9267a82efb5b8304d44f79d7d5787c88633dde27a18a2b"
# rewrite in little endian (overkill)
outpointId = int(outpointId, 16).to_bytes(len(outpointId)//2, byteorder='big')[::-1].hex()
# 4. index of the previous tx
outpointIndex = int2hexStr(0,4) # 1st output
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
fee = 30000 #                                   FEE
amount = amountPrev - fee
assert amount > 0
assert amount <= amountPrev
amountStr = int2hexStr(amount, 8)
# 11. receiving address
receiveAddresWif = "1H83sqx7GtHLNfCGu4ptAUipnof3tXcS3"
receiveAddresHex = b58decode_check(receiveAddresWif).hex()[2:]
outputScript = "76a914" + receiveAddresHex + "88ac"
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
privKey = 1 # PRIVKEY (of the address in which the btc are locked)
# another privKey was used! the one that could redeem the locked btc  
msg = "test1 23oct2017 leonardo comandini"
(x_W, z), R = signAndCommit(privKey,h,msg,k = None)
# DER encoding
DERfollows = "30"
x_WDER = ("00" if x_W > 2**(256-1)-1 else "") + hex(x_W)[2:].zfill(64)
zDER   = ("00" if z   > 2**(256-1)-1 else "") + hex(  z)[2:].zfill(64)
x_WDER = "02" + hex(len(x_WDER)//2)[2:].zfill(2) + x_WDER
zDER   = "02" + hex(len(  zDER)//2)[2:].zfill(2) +   zDER
lenSig = hex(len(x_WDER + zDER)//2)[2:].zfill(2) 
hashCodeType = int2hexStr(1,1)
#pubKey = (1,1) # PUBKEY (of the address in which the btc are locked)
#pubKeyStr = ECpoint2compressedStr(pubKey)
pubKeyStr = "039697e867ae7c317d60e3b5e1cc9d35cadb1178c422e567ec4aee82c6f46a06f3"
lenPubKeyStr = hex(len(pubKeyStr)//2)[2:].zfill(2)

# 16. concatenate
DERsig = DERfollows + lenSig + x_WDER + zDER
lenDERsig = hex(len(DERsig)//2 + 1)[2:].zfill(2) # +1 is for hashCodeType
DERsig = lenDERsig + DERsig + hashCodeType + lenPubKeyStr + pubKeyStr
# 17. We then replace the one-byte, varint length-field from step 5 with the  
#     length of the data from step 16. The length is 106 bytes, or 0x6a bytes: 6a
lenSigPK = hex(len(DERsig)//2)[2:].zfill(2)
DERsig = lenSigPK + DERsig
# 18. And we replace the temporary scriptSig from Step 6 with the data  
#     structure constructed in step 16.

# 19. We finish off by removing the four-byte hash code type we added in  
#     step 13, and we end up with the following stream of bytes, which is the final transaction:
finalTx = version + numInput + outpointId + outpointIndex + \
          DERsig + sequenceNumber + numOutput + amountStr + \
          lenOutputScript + outputScript + nlocktime
print("\n", finalTx, sep="")

nBytesFinalTx = len(finalTx)//2 # 193
# maybe an assert?
# source https://bitcoin.stackexchange.com/questions/1195/how-to-calculate-transaction-size-before-sending
# see Edit2
# N = numIn*148 + numOut*34 + 10 # case P2PKH # our case 1*148+1*34+10=192
# assert nBytesFinalTx in (N-1,N,N+1)

# check if the fees make sense with the market
print("\nSatoshis per byte:",fee/nBytesFinalTx)

# receipt
print("\n*** Receipt:")
print("     - txid :", txRawStr2txId(finalTx))
print("     - ind  :", 0) # temp
print("     - msg  :", msg)
print("     - R    :", ECpoint2compressedStr(R))

### decompostition of the raw transaction
#
#01000000 ........................................................... version
#01 ................................................................. numInput
#219d738419651dff4f9267a82efb5b8304d44f79d7d5787c88633dde27a18a2b ... outpointId
#00000000 ........................................................... outpointIndex
# ................................................................... DERsig 
#                  (it will be different for each rerunning, unless the eph privKey repeats)
#6c .................................................................  - bytes redeem script
#49 .................................................................  - bytes sig script
#30 .................................................................  - DER follows
#46 .................................................................  - bytes sig
#02 .................................................................  - int follows
#21 .................................................................  - bytes x_W
#00f529fe1624b0851ec133ac2feeee5ec138d0879942231690ec6c1fe3b4cf491e .  - x_W
#02 .................................................................  - int follows
#21 .................................................................  - bytes z
#00e600b9f8e1a0e5af5a87b346980d4c8501a3f72159aa7b8291b82fc16431f7b9 .  - z
#01 .................................................................  - sighashcode
#21 .................................................................  - bytes pubKey
#03 .................................................................  - y_pubKey_parity
#9697e867ae7c317d60e3b5e1cc9d35cadb1178c422e567ec4aee82c6f46a06f3 ...  - x_pubKey 
#ffffffff ........................................................... sequenceNumber
#01 ................................................................. numOutput
#20bf020000000000 ................................................... amount
#19 ................................................................. lenOutputScript
#76a914030c8a43b75b3109875c94139b2b95734090737888ac ................. outputScript
#00000000 ........................................................... nlocktime