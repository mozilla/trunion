# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict

import re
import time

import crypto

# From https://github.com/mozilla/browserid/blob/dev/lib/sanitize.js
EMAIL_REGEX = re.compile("^[-\w.!#$%&'*+/=?\^`{|}~]+@[-a-z\d_]+(\.[-a-z\d_]+)+$",
                         re.I)
PROD_URL_REGEX = re.compile("^https?:\/\/[-a-z\d_]+(\.[-a-z\d_]+)*(:\d+)?$", re.I)

# TODO
#    Don't permit other than the required fields to be safe:
#      typ, nbf, iss, iat, detail, verify, product(url, storedata),
#      user(type, value)

def valid_receipt(request):
    try:
        receipt = request.json_body
    except ValueError:
        raise HTTPBadRequest('Invalid JSON')

    now = long(time.time())

    for key in ('detail', 'verify', 'user', 'product', 'iss', 'iat', 'nbf'):
        if key not in receipt:
            raise HTTPBadRequest('missing %s' % key)

    # Verify the time windows
    #
    # Note: these checks should really reflect a window of opportunity taking
    #       clock drift and processing queue length/times into account
    #
    # Also, if we aren't going to revoke then the checks against signing['exp']
    # should definitely include a window
    signing = crypto.KEYSTORE.cert_data
    if receipt['iss'] not in request.registry.settings['trunion.permitted_issuers']:
        raise HTTPConflict('Bad issuer')
    if receipt['nbf'] < signing['iat']:
        raise HTTPConflict('nbf < iat')
    if receipt['nbf'] > signing['exp']:
        raise HTTPConflict('nbf > exp')
    if receipt['iat'] < signing['iat']:
        raise HTTPConflict('iat < iat')
    if receipt['iat'] > signing['exp']:
        raise HTTPConflict('iat > exp')
    if receipt['iat'] > now:
        raise HTTPConflict('iat in the future')

    try:
        valid_user(receipt['user'])
    except Exception, e:
        raise

    try:
        valid_product(receipt['product'])
    except Exception, e:
        raise


def valid_user(obj):
    if type(obj) != dict:
        raise HTTPBadRequest('Invalid user struct: not a dict')
    if 'type' not in obj:
        raise HTTPBadRequest('Invalid user struct: no type defined')
    if 'value' not in obj:
        raise HTTPBadRequest('Invalid user struct: invalid value')
    if obj['type'] not in ('email', 'directed-identifier'):
        raise HTTPBadRequest('Invalid user struct: unknown type')
    if obj['type'] == 'email' and not EMAIL_REGEX.match(obj['value']):
        raise HTTPBadRequest('Invalid user struct: invalid value')
    return True


def valid_product(obj):
    if type(obj) != dict:
        raise HTTPBadRequest('Invalid product struct: not a dict')
    if 'url' not in obj:
        raise HTTPBadRequest('Invalid product struct: no URL provided')
    if 'storedata' not in obj:
        raise HTTPBadRequest('Invalid product struct: no storedata')
    if not PROD_URL_REGEX.match(obj['url']):
        raise HTTPBadRequest("Invalid product struct: URL doesn't look like HTTPS")
    if len(obj['storedata']) < 1:
        raise HTTPBadRequest('Invalid product struct: storedata appears to be empty')
    return True
