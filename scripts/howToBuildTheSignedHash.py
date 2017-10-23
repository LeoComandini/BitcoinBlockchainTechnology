# -*- coding: utf-8 -*-
"""
Created on Mon Oct 23 12:44:30 2017

@author: Leonardo
"""
from hashlib import sha256
# from https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx?noredirect=1&lq=1

### Unsigned transaction
# 01000000 ........................................................... Version
# 01 ................................................................. Number of inputs
# eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2 ... Outpoint ID
# 01000000 ........................................................... Outpoint index
# 19 ................................................................. Length of the (temporary) scriptSig
# 76a914010966776006953d5567439e5e39f86a0d273bee88ac ................. ScriptPubKey to redeem
# ffffffff ........................................................... Sequence number
# 01 ................................................................. Number of outputs
# 605af40500000000 ................................................... Amount
# 19 ................................................................. Length of the output script 
# 76a914097072524438d003d23a2f23edb65aae1bb3e46988ac ................. Actual output script
# 00000000 ........................................................... Nlocktime
# 01000000 ........................................................... Hash code type

rawTxUnsignedStr = "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac0000000001000000"
rawTxUnsignedBytes = int(rawTxUnsignedStr, 16).to_bytes(len(rawTxUnsignedStr)//2, byteorder='big')
hTx = sha256(sha256(rawTxUnsignedBytes).digest()).digest().hex()
print(hTx)
print("9302bda273a887cb40c13e02a50b4071a31fd3aae3ae04021b0b843dd61ad18e")

