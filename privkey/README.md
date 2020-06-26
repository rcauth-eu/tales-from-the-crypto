# RCauth branch and repository

This branch contain a few extra scripts based on privkey.pem in
https://github.com/stfc/tales-from-the-crypto/

## Scripts and usage
To extract a key, use `convert.py`, to reconstruct a key, use
`convert_revert.py`.

The aim is to have:
- simple scripts that do all the steps
- read from/write to pipe to allow openssl commands as input/output
- writes no intermediate data on disk

### NOTES
- You will need to adapt the line starting with `input_cmd`.   
  For `convert.py` it should produce an unencrypted rsa key on stdout, for
  `convert_revert.py` it should `cat` a file with the output from `convert.py`.
- The test private key has password `test`.
- You can use the binary or ascii random data in `example_data/`.

### Examples

```
./convert.py example_data/random_bin 0 example_data/random_asc 1000 > xor_data
```

```
./convert_revert.py example_data/random_bin 0 example_data/random_asc 1000 > testkey.pem
```

To verify:

```
openssl rsa -in testkey.pem | diff - example_data/privkeyrsa_plain.pem
```

# Private Key Deconstruction and Reconstruction

An RSA private key (as created with, for example, OpenSSL) contains a
lot of redundant information.  The purpose of this code is to extract
the (almost) minimal information needed, and, in turn rebuild the key
from this information.  Of course in production applications one would
do one or the other but not both; the idea being that backing up or
sharing - or hiding - only a prime would be easier than the whole key.

## Requirements

In addition to its functional requirements - that it does as described -
this code has some slightly unusual requirements on the
implementation.

- Must be a standalone script
  - Easy to copy around without tarring up dependencies
  - No compilation required
  - Can work on low spec'ed machines
- Must not rely on non-standard modules
  - Designed to work on offline machines with a close to default OS
- Must be as portable as possible
  - Can run on older systems (and future systems)
  - Can run on a minimally installed system

## Implementation

Not many languages have native BigInts.  Python and Common Lisp do,
but the latter needs compilation for the target system (or a runtime
environment).

### Python version

This code is written in Python.  Unlike Common Lisp, Python is highly
version dependent, with functions appearing and disappearing.  This
code was written with 3.5, but has been tested to work with 3.3 through
to 3.7.  It does not work with 3.2 (or, presumably, earlier.)  See the
separate file on portability tests.

# Acknowledgments

This code was written to support tasks in GridPP, the UK Grid for
particle physics (www.gridpp.ac.uk) and EOSC Hub (www.eosc-hub.eu);
the latter being funded by Horizon2020 under grant agreement 777536.

It used GNU Emacs 24.5 on Debian Stretch with Python 3.5.3.

The work presented here builds on work presented at the CAOPS working
group meeting of the Open Grid Forum 23 in Barcelona, June 2008.
