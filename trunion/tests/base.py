# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

import os

from pyramid import testing
from mozsvc.config import load_into_settings
from mozsvc.tests.support import TestCase
import trunion.crypto as crypto

# Needed to inspect signatures
from base64 import b64decode
from M2Crypto.BIO import BIOError, MemoryBuffer
from M2Crypto.SMIME import PKCS7
from M2Crypto.X509 import X509_Stack
from M2Crypto.m2 import pkcs7_read_bio_der


class StupidRequest(testing.DummyRequest):
    """This is a stupid subclass so I can get a json_body property"""

    @property
    def json_body(self):
        return self.POST


class TrunionTest(TestCase):

    def setUp(self):
        self.path = '/1.0/sign'
        self.config = testing.setUp()
        self.ini = os.path.join(os.path.dirname(__file__), 'trunion-test.ini')
        settings = {}
        load_into_settings(self.ini, settings)
        self.config.add_settings(settings)
        self.config.include("trunion")
        # All of that just for this
        crypto.init(key=self.config.registry.settings['trunion.keyfile'],
                    cert=self.config.registry.settings['trunion.certfile'])

        self.signing = crypto.KEYSTORE.cert_data
        self._template = dict(typ="purchase-receipt",
                              product={"url": "https://grumpybadgers.com",
                                       "storedata": "5169314356"},
                              user={"type": "email",
                                    "value": "pickles@example9.com"},
                              iss=crypto.KEYSTORE.cert_data['iss'],
                              nbf=self.signing['iat'],
                              iat=self.signing['iat'],
                              detail="https://appstore.com/receipt/5169314356",
                              verify="https://appstore.com/verify/5169314356")

    def tearDown(self):
        testing.tearDown()


def response_to_pkcs7(blob):
    der = b64decode(blob)
    pkcs7_buf = MemoryBuffer(der)
    if pkcs7_buf is None:
        raise BIOError(Err.get_error())

    p7_ptr = pkcs7_read_bio_der(pkcs7_buf.bio)
    pkcs7 = PKCS7(p7_ptr, 1)
    return pkcs7


def get_signature_serial_number(pkcs7):
    # Fetch the certificate stack that is the list of signers.
    # Since there should only be one in this use case, take the zeroth
    # cert in the stack and return its serial number
    return pkcs7.get0_signers(X509_Stack())[0].get_serial_number()


def get_signature_cert_subject(pkcs7):
    # Fetch the certificate stack that is the list of signers.
    # Since there should only be one in this use case, take the zeroth
    # cert in the stack and return its serial number
    return pkcs7.get0_signers(X509_Stack())[0].get_subject().as_text()
