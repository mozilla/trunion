#!/usr/bin/env python
import argparse
import hashlib
import json
import jwt
import M2Crypto
import requests
import time
import struct

DEFAULT_ISSUER = 'https://marketplace.cdn.mozilla.net/public_keys/marketplace-root-pub-key.jwk'


class KeyMismatchError(Exception):
    pass


def day_string(arg):
    """
    Converts a string of the format "60m", "12h", "7d", "2w", and "1y" to
    seconds.
    """
    # expanded so we don't hit recursion limits
    s = lambda x: x
    m = lambda x: 60*x
    h = lambda x: 60*60*x
    d = lambda x: 24*60*60*x
    w = lambda x: 7*24*60*60*x
    y = lambda x: 365*24*60*60*x
    sum = 0
    i = ''
    for c in arg.strip():
        if c >= '0' and c <= '9':
            i += c
        elif c in "smhdwy":
            if i:
                sum += locals()[c](int(i))
                i = ''
            else:
                raise ValueError("Invalid day string format: \"%s\"" % arg)
        else:
            raise ValueError("Invalid day string format: \"%s\"" % arg)

    if sum == 0:
        raise ValueError("Invalid day string format: \"%s\"" % arg)
    return sum


# For production, we use an HSM stored private key which is access via
# OpenSSL's crypto engine support
def get_signing(args):
    if args.environment not in ('prod', 'production'):
        return M2Crypto.RSA.load_key(args.signing_id)
    else:
        M2Crypto.Engine.load_dynamic()
        engine = M2Crypto.Engine.Engine("chil")
        if not engine.set_default(M2Crypto.m2.ENGINE_METHOD_RSA):
            raise Exception("Could not inialize nCipher OpenSSL engine "
                            "properly. Make sure LD_LIBRARY_PATH "
                            "contains /opt/nfast/toolkits/hwcrhk")
        return engine.load_private_key(args.signing_id).get_rsa()


def new_rsa_key(args):
    if args.verbose:
        return M2Crypto.RSA.gen_key(args.bits, 0x10001)
    else:
        def NoOp(): pass
        return M2Crypto.RSA.gen_key(args.bits, 0x10001, NoOp)


def jwk2rsa(jwk):
    # Converts a JWK exponent or modulus from base64 URL safe encoded big endian
    # byte string to an OpenSSL MPINT
    def conv(a):
        __ = jwt.base64url_decode(a.encode('ascii'))
        return struct.pack('>I', len(__) + 1) + "\x00" + __

    try:
        return M2Crypto.RSA.new_pub_key((conv(jwk['jwk'][0]['exp']),
                                         conv(jwk['jwk'][0]['mod'])))
    except Exception, e:
        print "Failed to create RSA object from root's JWK: %s" % e
        raise e


def fetch_pubkey(url):
    # Fetch the issuer's public key from the URL provided by the key
    try:
        print "Fetching root pub key from %s" % url
        response = requests.get(url)
        if response.status_code == 200:
            jwk = json.loads(response.text)
            if url.strip() != jwk['jwk'][0]['kid']:
                raise KeyMismatchError("Fetched URL(%s) does not match the "
                                       "key ID of parsed JWK(%s)"
                                       % (url, jwk['jwk'][0]['kid']))
            return jwk
        else:
            raise requests.RequestException("Received a %d" % response.status)
    except requests.RequestException, e:
        print "Couldn't fetch %s: %s" % (url, str(e))
        raise e
    except Exception, e:
        print "Failed to convert fetched root pub key: %s" % e
        raise e


def jwkify(pub, keyid):
    if isinstance(pub, M2Crypto.RSA.RSA) \
            or isinstance(pub, M2Crypto.RSA.RSA_pub):
        pub = pub.pub()
    elif type(pub) != tuple:
        raise ValueError("jwkify expects an RSA object or a tuple")

    return dict(jwk=[{"alg": "RSA",
                      "kid": keyid,
                      "exp": jwt.base64url_encode(pub[0][4:]),
                      "mod": jwt.base64url_encode(pub[1][4:])}])


def save_jwsplat(args, typ, value):
    if hasattr(args, typ):
        filename = getattr(args, typ)
    else:
        try:
            filename = args.keyid + "." + typ
        except Exception, e:
            raise ValueError("Couldn't save as JWK to \"%s\": %s" % (args.keyid,
                                                                     e))
    with open(filename, 'w') as f:
        f.write(value)
    print "Saved to %s" % filename


#
# Subcommand functions
#

def newkey(args):
    key = new_rsa_key(args)

    try:
        key.save_key(args.pem, None)
        print "Saved to %s" % args.pem
    except AttributeError:
        key.save_key(args.keyid + ".pem", None)
        print "Saved to %s" % args.keyid + ".pem"
    except Exception, e:
        raise ValueError("Couldn't save as PEM to \"%s\": %s" % (args.pem, e))

    save_jwsplat(args, 'jwk', json.dumps(jwkify(key, args.keyid)))

    return key


def certify(args, priv=None):
    """Certifies an existing key from its PEM"""

    issued_at = int(time.time())
    expires = issued_at + args.lifetime

    if priv is None:
        try:
            priv = M2Crypto.RSA.load_key(args.pem)
        except Exception, e:
            raise ValueError("Unable to load key \"%s\": %s") % (args.pem, e)

    signing_priv = get_signing(args)
    signing_jwk = fetch_pubkey(args.issuer)
    # Make sure the published public key matches the key we are planning to
    # sign with
    signing_pub = jwk2rsa(signing_jwk)
    try:
        digest = hashlib.sha256(json.dumps(signing_jwk)).digest()
        signature = signing_priv.sign(digest, 'sha256')
        signing_pub.verify(digest, signature, 'sha256')
    except Exception, e:
        print "Heap big trouble, Batman!  The keys do not appear to be a ", \
              "matched pair: %s" % e
        raise e

    # The certification is a JWT containing a JWK:
    certificate = {
        "typ": "certified-key",
        "jwk": jwkify(priv, args.keyid)['jwk'],
        "nbf": long(issued_at),
        "exp": long(expires),
        "iat": long(issued_at),
        "price_limit": args.price_limit,
        "iss": args.issuer
    }

    envelope = jwt.encode(certificate, signing_priv,
                          header=dict(jku=args.issuer, typ='JWT', alg='RS256'),
                          algorithm='RS256')
    save_jwsplat(args, 'jwt', envelope)


def newcert(args):
    key = newkey(args)
    certify(args, key)


def pem2jwk(args):
    try:
        priv = M2Crypto.RSA.load_key(args.pem)
    except Exception, e:
        raise ValueError("Unable to load key \"%s\": %s") % (args.pem, e)

    with open(args.jwk, 'w') as f:
        json.dump(jwkify(priv, args.keyid), f)


def run(argv):
    # Command line handling
    cmdline = argparse.ArgumentParser(prog="keycert")
    cmdline.add_argument("--environment", "-e", dest="environment",
                         default='prod',
                         help="Set to \"prod\" if you want to use HSM to sign")
    cmdline.add_argument("--verbose", "-v", action='store_true')
    cmds = cmdline.add_subparsers(help="Available commands")

    cmd_newkey = cmds.add_parser('newkey', help='')
    cmd_certify = cmds.add_parser('certify', help="Issues a JWK-in-a-JWT "
                                                  "certificate from an "
                                                  "existing PEM file.")
    cmd_newcert = cmds.add_parser('newcert',
                                  help="Generates a new key and issues a new "
                                       "JWK-in-a-JWT certificate in one step.")
    cmd_pem2jwk = cmds.add_parser('pem2jwk', help='')

    # newkey
    cmd_newkey.add_argument('keyid',
                            default="appstore.mozilla.com-%s" %
                                time.strftime('%F', time.gmtime()),
                            help="The key ID.  Should be a file system "
                                 "friendly name")
    cmd_newkey.add_argument('--bits', '-b', dest='bits', default=2048,
                            help="Size of the key in bits, default 2048")
    cmd_newkey.set_defaults(func=newkey)

    # newcert
    cmd_newcert.add_argument('--bits', '-b', dest='bits', default=2048,
                             help="Size of the key in bits, default 2048")
    cmd_newcert.set_defaults(func=newcert)

    # certify
    cmd_certify.add_argument('pem', help="Path to the PEM file")
    cmd_certify.set_defaults(func=certify)

    # Shared args for certify and newcert subcommands
    for sub in (cmd_certify, cmd_newcert):
        sub.add_argument('--keyid',
                         default="appstore.mozilla.com-%s" %
                             time.strftime('%F', time.gmtime()),
                         help="The key ID.  Should be a file system "
                              "friendly name")
        sub.add_argument('--signing-key', dest='signing_id',
                         help="Path to the signing key PEM or HSM's ID for "
                              "signing key")
        sub.add_argument('--lifetime', type=day_string, default='2w',
                         help="Life time of the certificate be expiration")
        sub.add_argument('--issuer', default=DEFAULT_ISSUER,
                         help="URL for the signing/issuer's JWK")
        sub.add_argument('--price-limit', default=100)

    # pem2jwk
    cmd_pem2jwk.add_argument('pem', help='Path to the PEM file')
    cmd_pem2jwk.add_argument('--keyid',
                             default="appstore.mozilla.com-%s" %
                                 time.strftime('%F', time.gmtime()),
                             help="The key ID.  Should be a file system "
                                  "friendly name")
    cmd_pem2jwk.add_argument('--jwk', default=None, help="")
    cmd_pem2jwk.set_defaults(func=pem2jwk)

    args = cmdline.parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    import sys
    run(sys.argv[1:])
