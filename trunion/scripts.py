# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

import os
import sys
from trunion.utils import check_keys_from_config as _check_keys


def check_keys():
    if len(sys.argv) != 2:
        raise ValueError("Usage:  %s <path to trunion INI file>" % sys.argv[0])

    if not os.path.exists(sys.argv[1]):
        raise ValueError("'%s' doesn't exist" % sys.argv[1])

    _check_keys(sys.argv[1])
