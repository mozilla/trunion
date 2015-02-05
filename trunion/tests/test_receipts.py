# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict

from trunion.tests.base import StupidRequest, TrunionTest
from trunion.validators import valid_receipt


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

        post = dict(self._template,
                    product={'url': 'gopher://yoyodyne-propulsion.com'})
        request = StupidRequest(path=self.path, post=post)
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

        post = dict(self._template,
                    product={'url': 'https://grumpybadgers.com',
                             'storedata': ''})
        request = StupidRequest(path=self.path, post=post)
        self.assertRaises(HTTPBadRequest, valid_receipt, request)

    def test_validate_protocol(self):
        for url in ['http://f.com', 'https://f.com', 'app://f.com']:
            assert StupidRequest(path=self.path,
                                 post=dict(self._template,
                                           product={'url': url,
                                                    'storedata': 's'}))

        # These aren't really accurate tests any longer
        #
        # post = dict(self._template,
        #             product={'url': 'https://grumpybadgers.com',
        #                      'storedata': "Mr. A Square, Flatland"}))
        # request = StupidRequest(path=self.path, post=post)
        # self.assertRaises(HTTPBadRequest, valid_receipt, request)

        # post = dict(self._template,
        #             product={'url': 'https://grumpybadgers.com',
        #                      'storedata': 200.01}))
        # request = StupidRequest(path=self.path, post=post)
        # self.assertRaises(HTTPBadRequest, valid_receipt, request)
