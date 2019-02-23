#!/usr/bin/env python3
#
# https://stackoverflow.com/questions/6908143/should-i-put-shebang-in-python-scripts-and-what-form-should-it-take

# This code is designed to regenerate a private key from a public key
# and one of the primes.  The purpose of this approach is that sometimes one
# needs to back up or transport a private key in a secure way, and it can
# be useful to minimise the number of bytes that need to be transferred.
#
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

debug = False

# End user customisable parts


import argparse
import re
from base64 import b64decode, b64encode
from math import log,ceil
from sys import version_info



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


def lcm(a,b):
    """ Least Common Multiple """
    g = egcd(a,b)
    # g[2] is by definition a divisor of a (and of b), but '/' would make a float...
    return abs((a//g[2]) * b)


def inv(k,m):
    """ Inverse of k, modulo m """
    g = egcd(k,m)
    if(g[2] != 1):
        raise ArithmeticError("Cannot invert {} modulo {}".format(k,m))
    # Now g[0]*k + g[1]*m == g[2] == 1
    return g[0] % m


def powexp(a, k, m):
    """ Calculate a**k (modulo m) """
    if(k < 0):
        raise ValueError("Unwilling to raise to negative exponent; consider calling 'inv' if appropriate")
    result = 1
    b = a
    while(k):
        if(k & 1):
            result = (result * b) % m
        k >>= 1
        b = (b*b) % m
    return result


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


def testprivkey(x, mod, e, d):
    """ Given a modulus and encryption and decryption exponents, test by encrypting and decrypting a value x """
    if(x < 0 or x >= mod):
        raise ValueError("x out of range")
    return powexp( powexp(x, e, mod), d, mod) == x





# Reading functions


def tryifpem(octets):
    """ Check if octets might be PEM formatted and convert to DER; returning the decoded octets (= unchanged if they were not PEM encoded) plus a string of what entity was encoded (if available) """
    k = len(octets)
    s1 = b'-----BEGIN '
    if(k >= len(s1) and octets[0:len(s1)] == s1):
        # OK, it is probably PEM formatted...
        # https://stackoverflow.com/questions/606191/convert-bytes-to-a-string
        if(p2):
            s = octets
        else:
            s = octets.decode("ASCII")
        # re.fullmatch is only in version 3.4...
        pem = re.compile('-----BEGIN ([A-Z ]+)-----\n(.*)\n-----END ([A-Z ]+)-----$', re.DOTALL)
        o = pem.match(s)
        if(o):
            if(o.group(1) != o.group(3)):
                raise RuntimeError("Mismatched begin/end");
            what = o.group(1)
            try:
                # validate=False makes the decoder accept embedded newlines
                if(p2):
                    val = b64decode(o.group(2), altchars=None)
                else:
                    val = b64decode(o.group(2), altchars=None, validate=False)
            except binascii.Error as e:
                raise RuntimeError("Failed to parse Base64: {}".format(e.args[0]))
        else:
            raise RuntimeError("Doesn't match PEM header/footer")
        return (val, what)

    # Not PEM...
    return (octets, None)



def readintvasn1(octets, offs, size):
    """ Read an integer value at position offs, returning the integer and the updated offset """
    v = 0
    while(offs < size):
        v <<= 8
        v |= octets[offs]
        offs += 1
    if(debug):
        print("readintvasn1: read {}".format(v))
    return (v, size)


def readoidvasn1(octets, offs, size):
    """ Read an oid value at offset offs, within size, returning the OID as an integer list plus the new offset """
    oid = []
    first = True
    while( offs < size ):
        # Get the next integer, and update the offset
        i,offs = readintvasn1(octets, offs, size)
        # The first integer encodes the first two arcs
        if(first):
            oid = list( divmod(i,40) )
            first = False
        else:
            oid.append(i)
    return (oid, offs)


def readbitstringvasn1(octets, offs, size):
    """ Read a bit string at offset offs, upper bound size """
    if(size-offs < 2):
        raise ValueError("Bit string data too short at offset {}".format(offs))
    pad = octets[offs]
    if(pad > 7):
        raise ValueError("Illegal pad count {} at bit string at offset {}".format(pad,offs))
    offs += 1
    val = 0
    while(offs < size):
        val = (val << 8) | octets[offs]
        offs += 1
    # Check that the padding bits are zero
    if( val & ((1 << pad)-1) > 0 ):
        raise ValueError("Nonzero padding bits found at bit string")
    val >>= pad
    return (val, offs)
    

# Generic reader of TLVs; this doesn't need to read everything, just sequences, integers, OIDs, and NULL
# and bit strings and ...
def readtlvasn1(octets, offs, size):
    """ Read and try to parse octets from offs (inclusive) to size (not included) """
    if(debug):
        tmp = octets[offs : size]
        print("readtlvasn1 <= {}".format(tmp.hex()))
    if(offs+1 >= size):
        raise ValueError('tryparseasn1: offset value out of range at offset {}'.format(offs))
    tag = octets[offs] ; offs+= 1
    leng = octets[offs] ; offs+= 1
    if(p2):
        # In Python2 octets is a string
        pass
    if(leng & 0x80):
        nbytes = leng & 0x7F 
        if(offs + nbytes >= size):
            raise ValueError('tryparseasn1: insufficent data for length at offset {}'.format(offs))
        leng = 0
        while(nbytes > 0):
            # MSB first...
            leng = (leng << 8) | octets[offs]
            offs += 1
            nbytes -= 1
    if(debug):
        print("readtlvasn1 T={}, L={}".format(hex(tag), hex(leng)))
    # Now we have the Tag and the Length, and the offs where the Value begins
    val = []                    # Default; should be replaced below
    if(tag == 0x30):            # SEQUENCE
        val = []                # This one must be a list...
        o = offs                # Start...
        end = offs+leng
        while(o < end):
            v, o = readtlvasn1(octets, o, end)
            val.append(v)
        if(o > end):           # can't happen?
            raise ValueError('Read {} bytes, expected to read {} at offset {}'.format(o-offs, leng, offs))
        else:
            if(o < end):
                print("readtlvasn1: warning, unexpectedly read {} bytes at offset {}, expected {}".format(end-o, offs, leng))
            offs = end
    elif(tag == 0x02):          # INTEGER
        val, offs = readintvasn1(octets, offs, offs+leng)
    elif(tag == 0x05):          # NULL
        if(leng):
            print('Warning, found NULL with non-empty value at {}'.format(offs))
        offs += leng
    elif(tag == 0x06):
        val, offs = readoidvasn1(octets, offs, offs+leng)
    elif(tag == 0x03):
        val, offs = readbitstringvasn1(octets, offs, offs+leng)
    else:
        print('Warning, skipping unrecognised TAG {} found at offset {}'.format(tag,offs))
        offs += leng
    return (val, offs)



def readpubkey(filename):
    """ Attempt to read a public key from a file, returning modulus and exponent if successful """
    """ Currently supports only RSA public keys """
    try:
        with open(filename, 'rb') as f:
            # "If source is an integer, the array is initialised with zeros"
            pubkey = bytearray(source=maxpubkeyfilesize)
            pubkeysize = f.readinto(pubkey)
        if(p2):
            pubkey = bytearray(pubkey)
        data = readtlvasn1(pubkey, 0, pubkeysize)
    except OSError as e:
        print('Failed to read file {}: {}'.format(filename,e.args))
    raise RuntimeError("This needs more work!")
    #return (mod, exp)
    return data[0]


def readprivkey(filename):
    """ Attempt to read a private key from a file, returning the list of nine integers expected """
    """ The private key must be unencrypted RSA """
    with open(filename,'rb') as f:
        privkey = f.read()
        if(p2):
            privkey = bytearray(privkey)
        asn, what = tryifpem(privkey)
        if(what and debug):
            print("Found '{}'".format(what))
        if(p2):
            # Necessary(?) portability hack; fortunately bytearray(..) is idempotent
            asn = bytearray(asn)
        data = readtlvasn1(asn, 0, len(asn))
    if(debug):
        print("Received {}".format(data[0]))
    return data[0]



# Writing functions

def writeint7asn1(v):
    """ Write an integer in seven bits encoding into a byte array which is returned """
    if(v < 0):
        raise ValueError("writeint7asn1 negative value")
    elif(0 == v):
        return bytearray(1)
    m = []                      # Stack so we get MSB first
    while(v):
        m.insert(0, v & 0x7f)
        v >>= 7
    octets = bytearray(len(m))
    offs = 0
    while(m):
        octets[offs] = m.pop(0)
        if(m):
            octets[offs] |= 0x80 # continuation
        offs += 1
    return octets


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


def writeprivkey(filename, pkey, form):
    """ Write a private key to a file, optionally formatting it as DER or PEM """
    octets = writeseqtlvasn1(pkey)
    if(form == 'der'):
        with open(filename, "wb") as f:
            f.write(octets)
    elif(form == 'pem'):
        with open(filename, "w") as f:
            f.write('-----BEGIN RSA PRIVATE KEY-----\n')
            octets = b64encode(octets)
            s = octets.decode()
            for i in range(0,len(s),64):
                f.write( s[i:i+64] )
                f.write( '\n' )
            f.write('-----END RSA PRIVATE KEY-----\n')
    else:
        raise ValueError("Unknown format requested: {}, expected 'pem' or 'der'".format(form))



# Read a (PEM or DER formatted) private key

pk = readprivkey('privkey.pem')

# Extract the public key and the first prime
mod, exp, p1 = pk[1], pk[2], pk[4]

# Now reconstruct the private key...
rpk = mkprivkey(mod, exp, p1)

writeprivkey('privkey.tmp', rpk, 'pem')


