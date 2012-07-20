#!/usr/bin/env python

#
# TODO:
#
#  - Add a --verbose option with more output
#

import sys, ConfigParser, struct
import M2Crypto, hashlib, jwt, json, requests

# Convert a JWK exponent or modulus from base64 URL safe encoded big endian
# byte string to an OpenSSL MPINT
def conv(a):
    __ = jwt.base64url_decode(a.encode('ascii'))
    return struct.pack('>I', len(__) + 1) + "\x00" + __


def check_keys(certfile, keyfile):
    # Load the private key
    try:
        priv = M2Crypto.RSA.load_key(keyfile)
    except Exception, e:
        print "Failed ot load private key:\n\t%s\n" % e
        sys.exit(1)

    # Buffer the file contents for later verification
    with open(certfile) as f:
        cert_data = f.read().encode('ascii')

    # Load but don't verify the JWK-in-a-JWT certificate.
    try:
        cert = jwt.decode(cert_data, verify=False)
    except Exception, e:
        print "Failed to decode JWT: %s" % e

    # Convert the JWK into a form usable by M2Crypto
    try:
        pub = M2Crypto.RSA.new_pub_key((conv(cert['jwk'][0]['exp']),
                                        conv(cert['jwk'][0]['mod'])))
    except Exception, e:
        print "Failed to create RSA object from certificate's JWK: %s" % e
        sys.exit(1)

    # Fetch the issuer's public key from the URL provided by the key
    try:
        print "Fetching root pub key from %s" % cert['iss']
        response = requests.get(cert['iss'])
        if response.status_code == 200:
            jwk = json.loads(response.text)
            root = M2Crypto.RSA.new_pub_key((conv(jwk['jwk'][0]['exp']),
                                             conv(jwk['jwk'][0]['mod'])))
    except requests.RequestException, e:
        print "Couldn't fetch %s: %s" % (cert['iss'], str(e))
        sys.exit(1)
    except Exception, e:
        print "Failed to convert fetched root pub key: %s" % e
        sys.exit(1)

    # Verify that our certificate has a valid signature
    try:
        __ = jwt.decode(cert_data, root)
    except Exception, e:
        print "Failed to verify root key signature on certificate: %s" % e
        sys.exit(1)

    # Check that our private key and public key halves match
    try:
        digest = hashlib.sha256(cert_data).digest()
        signature = priv.sign(digest, 'sha256')
        pub.verify(digest, signature, 'sha256')
    except Exception, e:
        print "Heap big trouble, Batman!  The keys do not appear to be a matched pair: %s" % e
        sys.exit(1)

    print "Looks good."


def check_keys_from_config(path):
    config = ConfigParser.ConfigParser()

    try:
        config.read(path)
    except ConfigParser.Error, e:
        print "INI file doesn't seem to be parseable by ConfigParser: %s" % e
        sys.exit(1)

    try:
        certfile = config.get('trunion', 'certfile')
        keyfile = config.get('trunion', 'keyfile')
    except ConfigParser.NoOptionError:
        print "keyfile or certfile options are missing from the trunion " \
              "section of the config."
        sys.exit(1)

    check_keys(certfile, keyfile)
