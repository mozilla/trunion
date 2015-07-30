# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

import os

from pyramid import testing
from mozsvc.config import load_into_settings
from mozsvc.tests.support import TestCase
from trunion.tests.base import StupidRequest

from trunion.views import status
import trunion.crypto as crypto


class TrunionStatusTest(TestCase):

    def setUp(self):
        self.path = '/status'
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

    def test_status(self):
        request = StupidRequest(path=self.path)
        response = status(request)
        self.assertEqual(response, {"status": 'true'})

    def tearDown(self):
        testing.tearDown()
