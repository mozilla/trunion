# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

import unittest
import os

from pyramid import testing
from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict
from mozsvc.config import load_into_settings

from signing_clients.apps import JarExtractor
from trunion.validators import valid_receipt
from trunion.views import sign_app
import trunion.crypto as crypto


class StupidRequest(testing.DummyRequest):
    """This is a stupid subclass so I can get a json_body property"""

    @property
    def json_body(self):
        return self.POST


class TrunionTest(unittest.TestCase):

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


class ValidateTest(TrunionTest):

    def test_validate_malformed_json(self):
        request = StupidRequest(path=self.path,
                                post=dict(nascar=dict(self._template)))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

    def test_validate_issuer(self):
        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          iss="Big Bob's Rodeo Dairy!"))
        self.assertRaises(HTTPConflict, valid_receipt, request)

    def test_validate_nbf(self):
        request = StupidRequest(path=self.path,
                                post=dict(self._template, nbf=0))
        self.assertRaises(HTTPConflict, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          nbf=self.signing['iat'] - 1))
        self.assertRaises(HTTPConflict, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          nbf=self.signing['exp'] + 1))
        self.assertRaises(HTTPConflict, valid_receipt, request)

    def test_validate_iat(self):
        request = StupidRequest(path=self.path,
                                post=dict(self._template, iat=0))
        self.assertRaises(HTTPConflict, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          iat=self.signing['iat'] - 1))
        self.assertRaises(HTTPConflict, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          iat=self.signing['exp'] + 1))
        self.assertRaises(HTTPConflict, valid_receipt, request)

    def test_validate_user(self):
        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user='not a dict!'))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={'type': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={'type': 'taco',
                                                'value': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={'type': 'email',
                                                'value': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          user={'type': 'email',
                                                'value': 'hal@9000'}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

    def test_validate_product(self):
        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product='not a dict!'))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={'url': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={'url': 'gopher://yoyodyne-propulsion.com'}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        request = StupidRequest(path=self.path,
                                post=dict(self._template,
                                          product={'url': 'https://grumpybadgers.com',
                                                   'storedata': ''}))
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        # These aren't really accurate tests any longer
        #
        #request = StupidRequest(path=self.path,
        #                        post=dict(self._template,
        #                                  product={'url': 'https://grumpybadgers.com',
        #                                           'storedata': "Mr. A Square, Flatland"}))
        #self.assertRaises(HTTPBadRequest, valid_receipt, request)

        #request = StupidRequest(path=self.path,
        #                        post=dict(self._template,
        #                                  product={'url': 'https://grumpybadgers.com',
        #                                           'storedata': 200.01}))
        #self.assertRaises(HTTPBadRequest, valid_receipt, request)


class TrunionAppsTest(unittest.TestCase):

    MANIFEST = """Manifest-Version: 1.0

Name: test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: 5BXJnAbD0DzWPCj6Ve/16w==
SHA1-Digest: 5Hwcbg1KaPMqjDAXV/XDq/f30U0=

Name: test-dir/nested-test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: 53dwfEn/GnFiWp0NQyqWlA==
SHA1-Digest: 4QzlrC8QyhQW1T0/Nay5kRr3gVo=
"""

    SIGNATURE = """Signature-Version: 1.0
MD5-Digest-Manifest: dughN2Z8uP3eXIZm7GVpjA==
SHA1-Digest-Manifest: rnDwKcEuRYqy57DFyzwK/Luul+0="""

    SIGNATURES = """Signature-Version: 1.0
MD5-Digest-Manifest: dughN2Z8uP3eXIZm7GVpjA==
SHA1-Digest-Manifest: rnDwKcEuRYqy57DFyzwK/Luul+0=

Name: test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: jf86A0RSFH3oREWLkRAoIg==
SHA1-Digest: 9O+Do4sVlAh82x9ZYu1GbtyNToA=

Name: test-dir/nested-test-file
Digest-Algorithms: MD5 SHA1
MD5-Digest: YHTqD4SINsoZngWvbGIhAA==
SHA1-Digest: lys436ZGYKrHY6n57Iy/EyF5FuI=
"""

    SHA1SUM = "7437d73905c40bd23b16f8543e7ba0a2c1e8df17"

    def setUp(self):
        self.path = '/1.0/sign_app'
        self.config = testing.setUp()
        self.ini = os.path.join(os.path.dirname(__file__), 'trunion-test.ini')
        settings = {}
        load_into_settings(self.ini, settings)
        self.config.add_settings(settings)
        self.config.include("trunion")
        # All of that just for this
        crypto.init(key=self.config.registry.settings['trunion.keyfile'],
                    cert=self.config.registry.settings['trunion.certfile'],
                    chain=self.config.registry.settings['trunion.chainfile'])

    def _extract(self, omit=False):
        return JarExtractor('trunion/tests/test-jar.zip',
                            'trunion/tests/test-jar-signed.jar',
                            omit_signature_sections=omit)

    def test_00_extractor(self):
        self.assertTrue(isinstance(self._extract(), JarExtractor))

    def test_01_manifest(self):
        extracted = self._extract()
        self.assertEqual(str(extracted.manifest), self.MANIFEST)

    def test_02_signature(self):
        extracted = self._extract()
        self.assertEqual(str(extracted.signature), self.SIGNATURE)

    def test_03_signatures(self):
        extracted = self._extract()
        self.assertEqual(str(extracted.signatures), self.SIGNATURES)

    def test_04_signatures_omit(self):
        extracted = self._extract(True)
        self.assertEqual(str(extracted.signatures), self.SIGNATURE)

    def test_05_sign_app(self):
        extracted = self._extract(True)
        request = StupidRequest(path="/1.0/sign_app",
                                post={'zigbert.sf': extracted.signatures})
        response = sign_app(request)
        from pprint import pprint
        pprint(dir(response))
        pprint(response)

    def tearDown(self):
        testing.tearDown()
