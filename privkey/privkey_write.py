#!/usr/bin/env python
#
# https://stackoverflow.com/questions/6908143/should-i-put-shebang-in-python-scripts-and-what-form-should-it-take

# This code is designed to regenerate a private key from a public key
# and one of the primes.  The purpose of this approach is that sometimes one
# needs to back up or transport a private key in a secure way, and it can
# be useful to minimise the number of bytes that need to be transferred.
#
# Adapted from privkey.py by Mischa Salle
# (C) UKRI-STFC 2019 Jens Jensen
#
# Python functions are very version dependent but this was written
# with Python 3.5 and might work with everything >= 3.2.
#
# This code is designed specifically to be a single file script with
# no external dependencies other than Python and the standard library.
# This is because it is designed to work on offline systems, with a
# read-only filesystem, so cannot rely on the usual tricks of having
# to pull in external dependencies.
#
# The current implementation contains more code than it strictly needs
# to perform the core task of converting between
# {pubkey,prime}<->{privkey}
#
# Although largely a spare time project, the work presented here was
# partially supported by GridPP (www.gridpp.ac.uk) and the EOSC Hub
# project which receives funding from the European Union Horizon2020
# research and innovation programme under the grant agreement number
# 777536
# 


# User customisable parts

# Maximal size of a public key _file_; set to -1 for no maximum
maxpubkeyfilesize = 16384

#debug = False
debug = True

# End user customisable parts


import argparse
import re
from base64 import b64decode, b64encode
import binascii
from math import log,ceil
from sys import version_info
import sys



# Since we need a monolithic file, and Python somehow needs to define
# functions before they are used, the file is divided into sections,
# using old fashioned page separators (ctrl-L).
#
# Section 0 Introduction (this section)
# Section 1 Big Integer functions
# Section 2 ASN.1 readers
# Section 3 ASN.1 writers


# Portability hack; for now we try to support Python 2.7 as well as 3.X
# Can't universally use names to address it because names are introduced only in 2.7
p2 = version_info[0] == 2
if(p2):
    if(version_info.minor != 7):
        print("Warning, for Python2 has been tested only with 2.7")
else:
    if(version_info.minor <= 2):
        print("Warning, currently not expected to work with Python3 earlier than 3.3")


def readparts():
    lines=sys.stdin.readlines()
    for line in lines:
        line=line.strip()
        if line.startswith("mod="):
            mod=int(line[4:],16)
        elif line.startswith("exp="):
            exp=int(line[4:])
        elif line.startswith("p1="):
            p1=int(line[3:],16)
    return (mod, exp, p1)


# Big integer functions


# gcd appears in version 3.5 of Python...(!) and _does_ work with bigints.
# However, we need egcd for modulo division.  See Knuth TAOCP vol 2 (3rd ed), section 4.5.2, algorithm X (p.342).
#
# We need a small vector but Python's built in array seems useless for this purpose - it cannot accommodate bigints.
# Even numpy arrays can't handle big integers?!
def egcd(a,b):
    """ Greatest Common Divisor, Euclid descent """
    if(a < 0 or b < 0):
        return egcd(abs(a),abs(b))
    if(a<b):
        h = egcd(b,a)
        return (h[1], h[0], h[2])

    # WLOG, a>=b>=0 now

    # Hand-knitted vectors (otherwise we can not get bigint vectors)
    u0, u1, u2 = 1, 0, a
    v0, v1, v2 = 0, 1, b

    # ... Python doesn't do tail recursion optimisation?
    while(v2 > 0):
        q = u2 // v2
        t0 = u0 - q * v0 ; t1 = u1 - q * v1 ; t2 = u2 - q * v2
        u0, u1, u2 = v0, v1, v2
        v0, v1, v2 = t0, t1, t2
    return (u0,u1,u2)


def inv(k,m):
    """ Inverse of k, modulo m """
    g = egcd(k,m)
    if(g[2] != 1):
        raise ArithmeticError("Cannot invert {} modulo {}".format(k,m))
    # Now g[0]*k + g[1]*m == g[2] == 1
    return g[0] % m


# <int>.to_bytes() appears only in Python 3.2
def to_bytes(i):
    """ Convert an integer to a big endian byte array like .to_bytes() in later versions of Python3 """
    if(0 > i):
        raise ValueError("Not designed for negative numbers")
    if(0 == i):
        octets = bytearray(1)
        return octets
    k = i.bit_length()
    leng = (k+7) // 8
    octets = bytearray(leng)
    while(i):
        leng -= 1
        if(leng < 0):
            raise RuntimeError("to_bytes: can't happen (1) when byteifying {}".format(i))
        octets[leng] = i & 0xff
        i >>= 8
    if( 0 != leng or octets[0] == b'\x00' ):
        raise RuntimeError("to_bytes: can't happen (2) when byteifying {}".format(i))
    return octets



def mkprivkey(mod, exp, p):
    """ Using a public key in mod and exp, and the secret prime p, generate a list of 9 integers that provide the information for the private key """
    pkey = [0,mod,exp]          # Version, public key
    q,r = divmod(mod,p)
    if(r != 0):
        raise ValueError("Prime does not match the public key")
    # Euler's Totient Theorem gives us the secret exponent; $\phi(pq)=(p-1)(q-1)$ for $p,q$ primes
    # This code would work best if p and q were primes!
    d = inv(exp, (p-1)*(q-1))
    pkey.append(d)
    pkey.append(p)              # We assume p is the _first_ of the primes
    pkey.append(q)
    pkey.append(inv(exp,p-1))   # "exponent1" associated with prime1 == p
    pkey.append(inv(exp,q-1))   # "exponent2" associated with prime2 == q
    pkey.append(inv(q,p))       # "coefficient"
    return pkey


# Writing functions

def writelengthasn1(length):
    """ Write Length into octets """
    octets = bytearray(1)
    if(length < 0x80):
        octets[0] = length
        return octets
    #o = length.to_bytes( length=u, byteorder='big', signed=False)
    o = to_bytes(length)
    u = len(o)
    octets[0] = 0x80 | u        # This will fail if the length is 2**(128*8)
    return octets+o


def writeinttlvasn1(i):
    """ Write non-negative integer into an octet string with full TLV """
    if(i < 0):
        raise ValueError("writeinttlvasn1: negative number not implemented")
    # Special case: a zero byte needs to be stored explicitly, not as a length zero integer
    if(i == 0):
        h = 1
    else:
        h = i.bit_length()
    # to_bytes is present in Python only as of 3.2
    m = to_bytes(i)
    length = len(m)

    pad = bytearray(0)
    # If the MSB in the top byte is 1, we need a zero byte padding
    if(m[0] >= 0x80):
        length += 1
        pad = bytearray(1)      # zero byte

    octets = bytearray(1) ; octets[0] = 2 # Tag: integer
    # Encode the length into byte array
    octets += writelengthasn1(length)
    octets += pad
    octets += m
    return octets


def writeseqtlvasn1(seq):
    octets = bytearray(0)
    for y in seq:
        # There must be a better way ...?
        what = type(y).__name__
        if(what == 'int'):
            octets += writeinttlvasn1(y)
        elif(what == 'list'):
            octets += writeseqtlvasn1(y)
        elif(what == 'long'):           # needed for Python2.7
            octets += writeinttlvasn1(y)
        else:
            raise ValueError("Don't know how to encode {} yet".format(what))
    header = bytearray(1)
    header[0] = 0x30            # Tag: sequence
    header += writelengthasn1(len(octets))
    return header+octets


def writeprivkey(pkey, form):
    """ Write a private key to a file, optionally formatting it as DER or PEM """
    octets = writeseqtlvasn1(pkey)
    if(form == 'der'):
        sys.stdout.write(octets)
    elif(form == 'pem'):
        sys.stdout.write('-----BEGIN RSA PRIVATE KEY-----\n')
        octets = b64encode(octets)
        s = octets.decode()
        for i in range(0,len(s),64):
            sys.stdout.write( s[i:i+64] )
            sys.stdout.write( '\n' )
        sys.stdout.write('-----END RSA PRIVATE KEY-----\n')
    else:
        raise ValueError("Unknown format requested: {}, expected 'pem' or 'der'".format(form))

# Read the sub-parts from stdin

(mod, exp, p1) = readparts()


# Now reconstruct the private key...
rpk = mkprivkey(mod, exp, p1)

writeprivkey(rpk, 'pem')
