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

debug = False
#debug = True

# End user customisable parts


import re
from base64 import b64decode
import binascii
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



def readprivkey():
    """ Attempt to read a private key from a file, returning the list of nine integers expected """
    """ The private key must be unencrypted RSA """
    privkey = sys.stdin.read()
    privkey = bytearray(privkey,"ASCII")
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


# Read a (PEM or DER formatted) private key

pk = readprivkey()


# Extract the public key and the first prime
mod, exp, p1 = pk[1], pk[2], pk[4]

print("mod=%x\nexp=%d\n p1=%x\n" % (mod,exp,p1))
