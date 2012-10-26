# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

""" Cornice services.
"""
from cornice import Service
import crypto
from validators import valid_receipt

sign = Service(name='sign', path='/1.0/sign', description="Receipt signer")

@sign.post(validators=valid_receipt)
def sign_receipt(request):
    # validators already confirmed the payload is valid JSON
    receipt = request.json_body

    # Part one of the certified receipt is
    # our ephemeral key's certificate
    result = [crypto.get_certificate()]

    # Part two of the certified_receipt is the
    # input receipt, signed with our software key.

    # Sign the receipt with our current ephemeral key
    result.append(crypto.sign_jwt(receipt))

    return {'receipt': '~'.join(result)}
