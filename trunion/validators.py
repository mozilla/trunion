# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Trunion
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Tilder (rtilder@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
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
    except:
        raise

    try:
        valid_product(receipt['product'])
    except:
        raise


def valid_user(obj):
    if type(obj) != dict:
        raise HTTPBadRequest('Invalid user struct: not a dict')
    if 'type' not in obj:
        raise HTTPBadRequest('Invalid user struct: no type defined')
    if 'value' not in obj:
        raise HTTPBadRequest('Invalid user struct: invalid value')
    if obj['type'] != 'email':
        raise HTTPBadRequest('Invalid user struct: unknown type')
    if not EMAIL_REGEX.match(obj['value']):
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
