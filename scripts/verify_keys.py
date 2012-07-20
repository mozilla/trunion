import os
import sys


usage = 'verify_keys.py [cert] [key]'

sys.path.append(os.path.join(
                 '..', '..', os.path.dirname(os.path.abspath(__file))))

from trunion.utils import check_keys


check_keys(sys.argv[1], sys.argv[2])
