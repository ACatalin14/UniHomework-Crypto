#!python2
import hashlib, struct, random
from datetime import datetime

ver = 0x20400000
prev_block = "00000000000000000006a4a234288a44e715275f1775b77b2fddb6c02eb6b72f"
mrkl_root = "2dc60c563da5368e0668b81bc4d8dd369639a1134f68e425a9a74e428801e5b8"
time_ = 0x5DB8AB5E
bits = 0x17148EDF

exp = bits >> 24
mant = bits & 0xffffff
target_hexstr = '%064x' % (mant * (1 << (8 * (exp - 3))))
target_str = target_hexstr.decode('hex')

########### Cazul 1 ##########

printStep = 1000000
printThreshold = 3000000005
maxTries = 3100000000 - 3000000000
tries = 0

nonce1 = 3000000000
while nonce1 < 3100000000:

    header = (struct.pack("<L", ver) + prev_block.decode('hex')[::-1] +
              mrkl_root.decode('hex')[::-1] + struct.pack("<LLL", time_, bits, nonce1))

    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()

    if nonce1 < 3000000005:
        print nonce1, hash[::-1].encode('hex')

    if hash[::-1] < target_str:
        print '\nAm gasit Nonce1:', nonce1
        print 'Blocul obtinut are hash:', hash[::-1].encode('hex')
        break

    if nonce1 > printThreshold:
        print 'Progres:', str(tries * 100 / maxTries) + '%'
        printThreshold = printThreshold + printStep

    nonce1 += 1
    tries += 1

########## Cazul 2 ##########

random.seed(datetime.now())

# Acesta este nonce-ul gasit pentru care se satisface dificultatea ceruta
# dupa prima rulare a codului pe Cazul 1
nonce1 = 3060331852

# 3 000 000 000 < nonce1 < nonce2 < 13 100 000 000
nonce2 = nonce1 + random.randint(1, 10000000000)

printStep = 1000000
printThreshold = nonce2
maxTries = 600000000
tries = 0

startNonce = nonce2

print '\nS-a inceput cu nonce:', startNonce

while nonce2 < startNonce + maxTries:

    header = (struct.pack("<L", ver) + prev_block.decode('hex')[::-1] +
              mrkl_root.decode('hex')[::-1] + struct.pack("<LLQ", time_, bits, nonce2))

    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()

    if hash[::-1] < target_str:
        print '\nS-au realizat', (tries + 1), ' teste'
        print 'Am gasit Nonce2:', nonce2
        print 'Blocul obtinut are hash:', hash[::-1].encode('hex')
        break

    if nonce2 > printThreshold:
        print 'Progres:', str(tries * 10000 / maxTries / 100.00) + '%'
        printThreshold = printThreshold + printStep

    nonce2 += 1
    tries += 1

if tries == maxTries:
    print 'Nu s-a gasit niciun nonce in toate cele', maxTries, 'de teste.'
