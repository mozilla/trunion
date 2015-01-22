# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

from cStringIO import StringIO
import os
import time
import unittest
from pyramid import testing
from mozsvc.config import load_into_settings
from mozsvc.tests.support import TestCase
from trunion.tests.base import (StupidRequest,
                                response_to_pkcs7,
                                get_signature_cert_subject)

from signing_clients.apps import JarExtractor
from trunion.views import sign_addon
import trunion.crypto as crypto
from trunion.ephemeral import EphemeralCA, EphemeralFactory


class TrunionAddonsTest(unittest.TestCase):

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
SHA1-Digest-Manifest: rnDwKcEuRYqy57DFyzwK/Luul+0=
"""

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

    ini_file = 'trunion-test.ini'

    def setUp(self):
        self.path = '/1.0/sign_addon'
        self.config = testing.setUp()
        self.ini = os.path.join(os.path.dirname(__file__), 'trunion-test.ini')
        settings = {}
        load_into_settings(self.ini, settings)
        # FIXME Just have a separate INI file
        settings['trunion.we_are_signing'] = 'addons'
        self.config.add_settings(settings)
        self.config.include("trunion")
        # All of that just for this
        settings = self.config.registry.settings
        crypto.init(key=settings['trunion.keyfile'],
                    cert=settings['trunion.certfile'],
                    chain=settings['trunion.chainfile'])

        crypto.init_ca(self.sectionify(settings, 'addons'),
                       self.sectionify(settings, 'dnbase'),
                       self.sectionify(settings, 'extensions'))

    def sectionify(self, settings, section):
        section_items = {}
        prefix = section + '.'
        for key, value in settings.iteritems():
            if key.startswith(prefix):
                section_items[key[len(prefix):]] = value
        return section_items

    def _extract(self, omit=False):
        return JarExtractor('trunion/tests/test-jar.zip',
                            'trunion/tests/test-jar-signed.jar',
                            omit_signature_sections=omit)

    def gen(self, name='SMRT'):
        dnbase = dict(C='US', ST='Denial', L='Calvinville',
                      O='Allizom, Cni.', OU='Derivative Knuckles')
        settings = dict(keysize=512, lifetime=365)
        e = EphemeralFactory(settings, dnbase)
        return e.new(name)

    def test_00_ephemeral_factory(self):
        key, req = self.gen()
        self.assertEqual(req.get_subject().as_text(),
                         "C=US, ST=Denial, OU=Derivative Knuckles, O=Allizom, "
                         "Cni., L=Calvinville, CN=SMRT")

    def test_01_ephemeral_ca(self):
        key1, req1 = self.gen('ephy-1')
        cert1 = crypto.KEYSTORE.addon_ca.certify(req1)
        key2, req2 = self.gen('ephy-2')
        cert2 = crypto.KEYSTORE.addon_ca.certify(req2)
        self.assertNotEqual(cert1.get_serial_number(),
                            cert2.get_serial_number())

    def test_05_sign_addons(self):
        """
        Bah!  This is currently horked because StupidRequest extends
        pyramid.testing.DummyRequest which is very much NOT a webob request
        alike object.
        """
        class formfile(object):
            def __init__(self, filename, signatures):
                self.filename = filename
                self.file = StringIO(str(signatures))

        extracted = self._extract(True)
        post = dict(addon_id='hot_pink_bougainvillea',
                    file=formfile('zigbert.sf', extracted))
        request = StupidRequest(path="/1.0/sign_addon", post=post)
        response = sign_addon(request)
        signature = response_to_pkcs7(response['zigbert.rsa'])
        self.assertEqual(get_signature_cert_subject(signature),
                         "OU=Pickle Processing, C=US, L=Calvinville, "
                         "O=Allizom, Cni., ST=Denial, "
                         "CN=hot_pink_bougainvillea")

    def tearDown(self):
        testing.tearDown()
