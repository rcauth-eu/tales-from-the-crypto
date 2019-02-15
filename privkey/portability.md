# Portability

Python versions may differ dramatically as functions are added,
removed, or modified, with each minor release.

Although intended to work with Python 3.2 and above, the code doesn't

## Testing

Using the `privkey.py` to read a private key, extract the public key
and a prime, and regenerate the private key into a new file and
finally compare the two files, we run the code in the following test
script:

```
#!/bin/sh
rm -f privkey.pem
if openssl genrsa -out privkey.pem 2048 >/dev/null 2>&1 ; then
	./privkey.py
	cmp 2>&1 >/dev/null privkey.pem privkey.tmp
	result=$?
else
	echo >&2 "Failed to generate key"
	result=5
fi
rm -f privkey.pem privkey.tmp
exit $result
```										

This is baked into a Docker image based on the desired Python version,
which is set up to run the test script and exit, and a container is
then run.

```
docker build --label privkey,test,python3.3 .
docker run --rm 4161f4bee979
```

## Results

### Python 3.7

Success.

### Python 3.6

Success.

### Python 3.5

Success.

### Python 3.4

Success.

### Python 3.3

Success.


### Python 3.2

```
Traceback (most recent call last):
  File "./privkey.py", line 173, in tryifpem
    val = b64decode(o.group(2), altchars=None, validate=False)
  File "/usr/local/lib/python3.2/base64.py", line 83, in b64decode
    raise TypeError("expected bytes, not %s" % s.__class__.__name__)
TypeError: expected bytes, not str
	  
During handling of the above exception, another exception occurred:
	  
Traceback (most recent call last):
  File "./privkey.py", line 419, in <module>
    pk = readprivkey('privkey.pem')
  File "./privkey.py", line 308, in readprivkey
    asn, what = tryifpem(privkey)
  File "./privkey.py", line 174, in tryifpem
    except binascii.Error as e:
    NameError: global name 'binascii' is not defined
```
