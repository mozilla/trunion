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

def valid_receipt(request):
    try:
        receipt = request.json_body
    except ValueError:
        request.errors.add('body', 'receipt', 'Invalid JSON')
        raise HTTPBadRequest()

    now = long(time.time())

    for key in ('detail', 'verify', 'user', 'product',):
        if key not in receipt:
            request.errors.add('body', 'receipt', 'Invalid JSON')
            raise HTTPBadRequest()

    # Verify the time windows
    #
    # Note: these checks should really reflect a window of opportunity taking
    #       clock drift and processing queue length/times into account
    if (receipt['iss'] != crypto.KEYSTORE.cert_data['iss']
        or receipt['nbf'] > now
        or receipt['iat'] > now
        or receipt['iat'] < crypto.KEYSTORE.cert_data['iat']):
        raise HTTPConflict()

    if not valid_user(receipt['user']):
        request.errors.add('body', 'receipt', 'Invalid user struct')
        raise HTTPBadRequest()

    if not valid_product(receipt['product']):
        request.errors.add('body', 'receipt', 'Invalid product struct')
        raise HTTPBadRequest()

def valid_user(obj):
    if (type(obj) != dict
        or 'type' not in obj
        or 'value' not in obj
        or obj['type'] != 'email'
        or not EMAIL_REGEX.match(obj['value'])):
            return False

def valid_product(obj):
    if (type(obj) != dict
        or 'url' not in obj
        or 'storedata' not in obj
        or not PROD_URL_REGEX.match(obj['url'])
        or type(obj['storedata']) != int):
            return False
