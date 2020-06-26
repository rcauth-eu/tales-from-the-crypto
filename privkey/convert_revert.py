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
# - reads the mod, exp and XOR-ed p1 (from stdin),
# - reads random data and offset (from file, optionally stdin),
# - XORs the XOR-ed p1 with both randoms using their respective offset,
# - re-assembles an unencrypted private key from mod, exp and p1,
# - converts the unencrypted private key to DES3 private key and prints it

import sys
import binascii
import subprocess
from subprocess import PIPE, Popen, CalledProcessError

# Input command:
# should print mod, exp and xor-ed data on stdout, output of something like:
# ./convert.py example_data/random_asc 10 example_data/random_bin 10
input_cmd=["cat", "xor_data"]

# path to privkey_write.py tool
privkey_write="./privkey_write.py"

# openssl cmd to convert unencrypted private key (output of privkey_write.py) in
# des3 encrypted
openssl_cmd=["openssl", "rsa", "-des3"]


# Check cmdline args: optionally one random can be input via stdin
if ( len(sys.argv)!=3 and len(sys.argv)!=5 ):
    sys.stderr.write("Usage: <random-file> <offset> [<random-file> <offset>]\n")
    sys.exit(1)

# First random, always file
try:
    # First try as ascii file, if that files, try as binary
    with open(sys.argv[1]) as f:
        xordata1 = bytearray(f.read(), "ASCII")
except UnicodeDecodeError:
    # Try as binary instead
    with open(sys.argv[1], mode="rb") as f:
        xordata1 = bytearray(f.read())
# offset in xordata1
offset1=int(sys.argv[2])

# Second offset/random: either file or stdin (then offset==0)
if (len(sys.argv) == 3):
    # Read second random from stdin
    sys.stderr.write("Enter second random: ")
    xordata2=bytearray(sys.stdin.readline().strip(), "ASCII")
    offset2=0
else:
    # Read second random from file
    try:
        # First try as ascii file, if that files, try as binary
        with open(sys.argv[3]) as f:
            xordata2 = bytearray(f.read(), "ASCII")
    except UnicodeDecodeError:
        # Try as binary
        with open(sys.argv[3], mode="rb") as f:
            xordata2 = bytearray(f.read())
    # offset in xordata2
    offset2=int(sys.argv[4])

# Verify that both xordata aren't the same
if (xordata1 == xordata2):
    sys.stderr.write("Error: both sets of random data are the same!\n")
    sys.exit(1)

# Read XOR-ed input key
try:
    input_data=subprocess.check_output(input_cmd)
except CalledProcessError as e:
    sys.stderr.write("ERROR: %s, exitval %s\n" %
                     (e.output, e.returncode))
    sys.exit(1)
# split input data on newlines
input_lines=input_data.decode('ASCII').split('\n')

# First and second lines contain mod and exp
mod=input_lines[0][4:]
exp=input_lines[1][4:]

# XOR-ed data is third line (as hex)
xor_bin=bytearray(binascii.unhexlify(input_lines[2][4:]))
# Create output bytearray of right length
outdata=bytearray(len(xor_bin))
# do the actual xor-in
for i in range(len(xor_bin)):
    outdata[i]=xor_bin[i] ^ xordata1[offset1+i] ^ xordata2[offset2+i]
    # Clear input data
    xor_bin[i]=0
for i in range(len(xordata1)):
    xordata1[i]=0
for i in range(len(xordata2)):
    xordata2[i]=0

# p1 is hex representation of binary XOR-ed data
p1=binascii.hexlify(outdata).decode('ASCII')

# Need to write mod, exp and p1 as stdin to privkey_write
# Note: str.format is tricky for python2/python3, better just use +
privkey_inp="mod="+mod+"\nexp="+exp+"\n p1="+p1+"\n"

# Convert params back into unencrypted key (in result)
try:
    pipe=subprocess.Popen(privkey_write,
                          stdin=PIPE,
                          stdout=PIPE,
                          close_fds=True)
    # Note: bytes(privkey_inp... is tricky since python3 wants encoding while
    # python2 not, encode is fine for both
    (key, err)=pipe.communicate(input=privkey_inp.encode())
except CalledProcessError as e:
    sys.stderr.write("ERROR: exitval %s\n" %
                     (e.returncode))

# Now convert to unencrypted key in result into encrypted private key
try:
    pipe=subprocess.Popen(openssl_cmd,
                          stdin=PIPE,
                          stdout=PIPE,
                          close_fds=True)
    # Note: bytes(inp... is tricky since 3 wants encoding and 2 not, encode is
    # fine for both
    (key_enc, err)=pipe.communicate(input=key)
except CalledProcessError as e:
    sys.stderr.write("ERROR: exitval %s\n" %
                     (e.returncode))
print(key_enc.decode('ASCII'))
