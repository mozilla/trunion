# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

from cStringIO import StringIO
import os

from pyramid import testing
from mozsvc.config import load_into_settings
from mozsvc.tests.support import TestCase
from trunion.tests.base import StupidRequest

from signing_clients.apps import JarExtractor
from trunion.views import sign_app
import trunion.crypto as crypto


class TrunionAppsTest(TestCase):

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
        post = dict(file=formfile('zigbert.sf', extracted))
        request = StupidRequest(path="/1.0/sign_app", post=post)
        response = sign_app(request)

    def tearDown(self):
        testing.tearDown()
