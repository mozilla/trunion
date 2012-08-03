import os
import sys
from optparse import OptionParser

sys.path.append(os.path.join(
                os.path.dirname(os.path.abspath(__file__)), '..'))

from trunion.utils import check_keys

parser = OptionParser(usage='verify_keys.py [-e expiry] [cert] [key]')
parser.add_option("-e", "--expires", type='int',
                  help='check that key is valid until now + expiry')


(options, args) = parser.parse_args()


check_keys(args[0], args[1], check_expiration=options.expires)
