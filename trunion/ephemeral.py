# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****


import time
from M2Crypto import ASN1, EVP, RSA, X509


class EphemeralCA(object):
    """
    A convenience object that tries to encompass the majority of the functions
    associated with a certificate authority.
    """
    def __init__(self, privkey, certificate, settings, extensions):
        # Key and certificate are loaded in trunion.crypto.KeyStore's methods
        # so we expect EVP.Pkey and X509.X509 alike objects
        self.key = privkey
        self.certificate = certificate
        self.settings = settings
        self.extensions = extensions

    def set_validity_period(self, cert):
        now = long(time.time())
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_time(now)
        cert.set_not_before(asn1)
        asn1 = ASN1.ASN1_UTCTIME()
        asn1.set_time(now + self.settings['cert_validity_lifetime'] * 24 * 60 * 60)
        cert.set_not_after(asn1)

    def certify(self, req):
        pubkey = req.get_pubkey()
        cert = X509.X509()
        cert.set_pubkey(pubkey)
        cert.set_version(2)  # 2 means X509v3
        #
        # We are explicitly using Python's default time type * 1000 to include
        # milliseconds.  While I don't expect to be generating these more often
        # than once a second I've be wrong before.
        #
        cert.set_serial_number(int(time.time() * 1000))
        self.set_validity_period(cert)

        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())

        cert.set_issuer(self.certificate.get_subject())

        # Some massaging is necessary for extensions if provided in OpenSSL
        # config file style
        if ('subjectKeyIdentifier' in self.extensions
                and self.extensions['subjectKeyIdentifier'] == 'hash'):
            self.extensions['subjectKeyIdentifier'] = cert.get_fingerprint()

        # Aaaaaand sign
        cert.sign(self.key, self.settings['signature_digest'])
        return cert


class EphemeralFactory(object):
    """
    Simply generating ephemeral keys and certificate requests based on settings
    passed in from the config
    """

    def __init__(self, settings, dnbase):
        self.key_size = settings.get('ephemeral_key_size', 2048)
        self.digest_alg = settings.get('signature_digest', 'sha1')
        self.dnbase = dnbase

    def new(self, identifier):
        # New key of the correct size
        key = EVP.PKey()
        key.assign_rsa(RSA.gen_key(self.key_size, 0x10001, lambda: None))

        # Generate the certreq
        request = X509.Request()
        request.set_pubkey(key)

        # Set the request's DN
        subject = request.get_subject()
        for k, v in self.dnbase.iteritems():
            # INI style parsers frequently convert key names to all lowercase
            # and M2Crypto's X509_Name class doesn't like that.
            setattr(subject, k.upper(), v)
        subject.CN = identifier

        # Sign the request
        request.sign(key, self.digest_alg)
        return key, request
