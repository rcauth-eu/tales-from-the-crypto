#!/usr/bin/env python
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# (C) Nikhef 2019 Mischa Salle

# Simple demonstrator program for the RCauth private key exchange. It
# - reads the private key (from stdin),
# - reads random data and offset (from file, optionally stdin),
# - extracts mod, exp and p1 from the private key,
# - XORs the p1 with both randoms using their respective offset
# - prints mod, exp and XOR-ed p1

import sys
import binascii
import subprocess
from subprocess import PIPE, Popen, CalledProcessError

# Input command:
# should read the private key and dump it on stdout:
input_cmd=["openssl", "rsa", "-in", "example_data/privkeyrsa.pem"]

# path to privkey_read.py tool
privkey_read="./privkey_read.py"


# Check cmdline args: optionally one random can be input via stdin
if ( len(sys.argv)!=3 and len(sys.argv)!=5 ):
    sys.stderr.write("Usage: <random-file> <offset> [<random-file> <offset>]\n")
    sys.exit(1)

# First random, always file
try:
    # First try as ascii file, if that fails, try as binary
    with open(sys.argv[1]) as f:
        xordata1 = bytearray(bytearray(f.read(), "ASCII").decode("hex"))
        #sys.stderr.write("Input 1 is ascii\n");
except UnicodeDecodeError:
    # Try as binary instead
    with open(sys.argv[1], mode="rb") as f:
        xordata1 = bytearray(f.read())
        #sys.stderr.write("Input 1 is binary\n");
# offset in xordata1
offset1=int(sys.argv[2])

# Second offset/random: either file or stdin (then offset==0)
if (len(sys.argv) == 3):
    # Read second random from stdin
    sys.stderr.write("Enter second random: ")
    xordata2 = bytearray(bytearray(sys.stdin.readline().strip(), "ASCII").decode("hex"))
    offset2=0
else:
    # Read second random from file
    try:
        # First try as ascii file, if that files, try as binary
        with open(sys.argv[3]) as f:
            xordata2 = bytearray(bytearray(f.read(), "ASCII").decode("hex"))
            #sys.stderr.write("Input 2 is ascii\n");
    except UnicodeDecodeError:
        # Try as binary
        with open(sys.argv[3], mode="rb") as f:
            xordata2 = bytearray(f.read())
            #sys.stderr.write("Input 2 is binary\n");
    # offset in xordata2
    offset2=int(sys.argv[4])

# Verify that both xordata aren't the same
if (xordata1 == xordata2):
    sys.stderr.write("Error: both sets of random data are the same!\n")
    sys.exit(1)

# Read private key
try:
    key=subprocess.check_output(input_cmd)
except CalledProcessError as e:
    sys.stderr.write("ERROR: %s, exitval %s\n" %
                     (e.output, e.returncode))
    sys.exit(1)

# Get params from private key
try:
    pipe=subprocess.Popen(privkey_read,
                          stdin=PIPE,
                          stdout=PIPE,
                          close_fds=True)
    (result, err)=pipe.communicate(input=key)
except CalledProcessError as e:
    sys.stderr.write("ERROR: exitval %s\n" %
                     (e.returncode))

# result is string with 3 lines: mod, exp and p1
# unfortunately, we can't really cleanup result or params
params=result.decode('ASCII').split('\n')

# First and second lines contain mod and exp
mod=params[0][4:]
exp=params[1][4:]

# Create p1_bin as bytearray so that we can overwrite
p1_bin=bytearray(binascii.unhexlify(params[2][4:]))

# Create output bytearray
outdata=bytearray(len(p1_bin))
# do the actual xor-in
for i in range(len(p1_bin)):
    outdata[i]=p1_bin[i] ^ xordata1[offset1+i] ^ xordata2[offset2+i]
    # Clear input data
    p1_bin[i]=0
for i in range(len(xordata1)):
    xordata1[i]=0
for i in range(len(xordata2)):
    xordata2[i]=0

result_bin=bytearray(binascii.hexlify(outdata))
print("mod=%s" % mod)
print("exp=%s" % exp)
print("XOR=%s" % result_bin.decode('ASCII'))

# Clear result array
for i in range(len(result_bin)):
    result_bin[i]=0
