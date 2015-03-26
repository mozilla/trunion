# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

#
# Wrapper for crypto functions
#

import jwt
import logging
import M2Crypto
import json
import re

CERTIFICATE_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+"
                            "-----END CERTIFICATE-----", re.S)

# Lame hack to take advantage of a not well known OpenSSL flag.  This omits
# the S/MIME capabilities when generating a PKCS#7 signature.
M2Crypto.SMIME.PKCS7_NOSMIMECAP = 0x200


class KeyStore(object):

    def __init__(self, key, cert, chain=None, engine=None):
        self.key_file = key
        self.cert_file = cert
        self.chain = chain
        self.cert_data = None
        self.engine = engine
        # I hate these hacks so much
        self.ca_cert = None
        self.factory = None
        self.addon_ca = None

        # SMIME object for signing apps
        self.smime = M2Crypto.SMIME.SMIME()

        # FIXME Verify that it's actually a paired set of keys
        self.set_key(self.key_file)
        self.load_jwt_cert(self.cert_file)
        self.load_smime_cert_chain(self.chain)

    def sign(self, data, hash_alg):
        return self.key.get_rsa().sign(data, hash_alg)

    def sign_app(self, data):
        return self.xpi_sign(self.smime, data)

    def sign_addon(self, identifier, data):
        # New ephemeral for each request
        e_key, e_req = self.factory.new(identifier)
        e_cert = self.addon_ca.certify(e_req)

        # Set up our SMIME object for signing
        smime = M2Crypto.SMIME.SMIME()
        smime.pkey = e_key
        smime.x509 = e_cert

        # Only one thing in the certificate stack: the ephemeral CA cert.
        # But the PCKS7 routines expect an X509_Stack type
        stack = M2Crypto.X509.X509_Stack()
        stack.push(self.addon_ca.certificate)
        smime.set_x509_stack(stack)

        pkcs7 = self.xpi_sign(smime, data)
        return pkcs7

    def xpi_sign(self, smime, data):
        # XPI signing is technically incompatible subset of JAR signing.  JAR
        # signing uses PKCS7 detached signatures.
        #
        # XPI signature verification goes belly up if there is an SMIME
        # capabilities so add the flag to prevent it being included
        pkcs7 = smime.sign(M2Crypto.BIO.MemoryBuffer(str(data)),
                           M2Crypto.SMIME.PKCS7_DETACHED
                           | M2Crypto.SMIME.PKCS7_BINARY
                           | M2Crypto.SMIME.PKCS7_NOSMIMECAP)
        pkcs7_buf = M2Crypto.BIO.MemoryBuffer()
        pkcs7.write_der(pkcs7_buf)
        return pkcs7_buf.read()

    def verify(self, digest, signature, alg):
        self.key.verify_init()
        self.key.verify_update(digest)
        return self.key.verify_final(signature)

    def encode_jwt(self, payload):
        header = dict(alg=u'RS256', typ='JWT', jku=self.cert_data['iss'])
        return jwt.encode(payload, self, header=header,
                          algorithm='RS256')

    def decode_jwt(self, payload):
        return jwt.decode(payload, self)

    def set_key(self, name):
        if self.engine:
            try:
                M2Crypto.Engine.load_dynamic()
                engine = M2Crypto.Engine.Engine(self.engine)
                if not engine.set_default(M2Crypto.m2.ENGINE_METHOD_RSA):
                    raise Exception("Could not inialize nCipher OpenSSL engine"
                                    " properly. Make sure LD_LIBRARY_PATH "
                                    "contains /opt/nfast/toolkits/hwcrhk")
                self.key = engine.load_private_key(name)
            except:  # I have no idea what might get raised
                logging.error("Failed to load key \"%s\" from HSM" % name,
                              exc_info=True)
                raise
        else:
            try:
                self.key = M2Crypto.EVP.load_key(name)
            except M2Crypto.BIO.BIOError:
                logging.error("Failed to load key: %s" % name, exc_info=True)
                raise
        # We short circuit the key loading functions in the SMIME class
        self.smime.pkey = self.key

    def load_jwt_cert(self, name):
        # FIXME  Need to verify that the pubkey in the cert does match the
        # signing key by doing a quick signature check
        try:
            with open(name, 'r') as f:
                self.certificate = f.read()
            try:
                self.cert_data = jwt.decode(self.certificate, verify=False)
            except jwt.DecodeError:
                # This may raise an exception but that's ok
                self.cert_data = json.loads(self.certificate)['jwk'][0]
        except:
            logging.error("Unable to load certificate for key '%s': cannot "
                          "find '%s.crt' file in working directory"
                          % (name, name))
            raise  # IOError("Unable to load certificate for key '%s'" % name)

    def load_smime_cert_chain(self, name):
        if not name:
            return
        try:
            with open(name, 'r') as f:
                chain = f.read()
                certs = CERTIFICATE_RE.finditer(chain)
                stack = M2Crypto.X509.X509_Stack()
                # The signing certificate should be the first in the stack.  It
                # isn't used in the stack as it has its own place.
                self.smime.x509 = M2Crypto.X509.load_cert_string(certs.next().group(0))
                for cert in certs:
                    _c = M2Crypto.X509.load_cert_string(cert.group(0))
                    stack.push(_c)
                self.smime.set_x509_stack(stack)
        except:
            logging.error("Unable to load SMIME certificates")
            raise

    def load_ca_cert(self, fname):
        self.ca_cert = M2Crypto.X509.load_cert(fname)


KEYSTORE = None


def init(*args, **kwargs):
    global KEYSTORE
    if KEYSTORE is None:
        KEYSTORE = KeyStore(*args, **kwargs)


def init_ca(addons, dnbase, extensions):
    # So many fugly hacks
    from trunion.ephemeral import EphemeralCA, EphemeralFactory
    KEYSTORE.factory = EphemeralFactory(addons, dnbase)
    KEYSTORE.ca_cert = addons['ca_cert_file']
    KEYSTORE.load_ca_cert(KEYSTORE.ca_cert)
    KEYSTORE.addon_ca = EphemeralCA(KEYSTORE.key, KEYSTORE.ca_cert, addons,
                                    extensions)


def sign(input_data):
    return KEYSTORE.sign(input_data, "sha256")


def sign_jwt(input_data):
    return KEYSTORE.encode_jwt(input_data)


def verify_jwt(input_data):
    return KEYSTORE.decode_jwt(input_data)


def get_certificate():
    return KEYSTORE.certificate


def sign_app(data):
    return KEYSTORE.sign_app(data)


def sign_addon(identifier, data):
    return KEYSTORE.sign_addon(identifier, data)
