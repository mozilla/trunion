import os
import sys
from trunion.utils import check_keys_from_config as _check_keys


def check_keys():
    if len(sys.argv) != 2:
        raise ValueError("Usage:  %s <path to trunion INI file>" % sys.argv[0])

    if not os.path.exists(sys.argv[1]):
        raise ValueError("'%s' doesn't exist" % sys.argv[1])

    _check_keys(sys.argv[1])
