import os
import M2Crypto
import logging
import time
import json
import crypto
import jwt
import hashlib

M2Crypto.Rand.rand_seed(os.urandom(1024))

def NoOp():
    pass

# Generates a keypair and returns a (certificate, privateKey) tuple
def generate_key(bits, expiry_timestamp, price_limit, issuer=None):
    rsaObj = M2Crypto.RSA.gen_key(bits, 0x10001, NoOp)

    return (rsaObj.as_pem(None), certify_key(rsaObj, expiry_timestamp,
					     price_limit, issuer))


def certify_key(privkey, expiry_timestamp, price_limit, issuer=None, issued_at=None):
    """ Expects an M2Crypto.RSA.RSA key for privkey """

    serialized = certificate(privkey, expiry_timestamp, price_limit, issuer,
			     issued_at)
    # Certify it:
    certified = crypto.sign_jwt(serialized)
    return certified


def certificate(privkey, expiry_timestamp, price_limit, issuer=None, issued_at=None,
		keyid=None):

    if issuer is None:
        issuer = crypto.KEYSTORE.kid

    if issued_at is None:
        issued_at = time.time()

    if keyid is None:
        keyid = "appstore.mozilla.com-%s" % time.strftime('%F', time.gmtime(issued_at))

    # The certification is a JWT containing a JWK:
    pubKey = privkey.pub()
    certificate = {
        "typ": "certified-key",
        "jwk": [ { "alg": "RSA",
                   "kid": keyid,
                   "mod": jwt.base64url_encode(pubKey[1][4:]),
                   "exp": jwt.base64url_encode(pubKey[0][4:]) } ],
        "nbf": long(issued_at),
        "exp": long(expiry_timestamp),
        "iat": long(issued_at),
        "price_limit": price_limit,
        "iss": issuer
    }
    return json.dumps(certificate)


def generate_root(bits, expires, keyid):
    """For generating test root ceritifcates"""

    print "\nWARNING: generate_root should only be used for testing!\n"

    rsaObj = M2Crypto.RSA.gen_key(bits, 0x10001, NoOp)

    # Create the JWK from the pubkey
    juke = dict(jwk=[ dict(alg="RSA", use='sig', kid=keyid,
                           exp=jwt.base64url_encode(rsaObj.pub()[0][4:]),
                           mod=jwt.base64url_encode(rsaObj.pub()[1][4:])) ])

    return (rsaObj.as_pem(None), json.dumps(juke))

