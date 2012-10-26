# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

"""
Runs the Application. This script can be called by any wsgi runner that looks
for an 'application' variable
"""
import os
from logging.config import fileConfig
from ConfigParser import NoSectionError
import site

ROOT = os.path.dirname(os.path.abspath(__file__))
if os.path.splitext(os.path.basename(__file__))[0] == 'cProfile':
    if os.environ.get('TRUNION_PATH'):
        ROOT = os.environ['TRUNION_PATH']
    else:
        print 'When using cProfile you must set $TRUNION_PATH'
        sys.exit(2)

path = lambda *a: os.path.join(ROOT, *a)

site.addsitedir(path('vendor'))
site.addsitedir(path('vendor/lib/python'))

# setting up the egg cache to a place where apache can write
os.environ['PYTHON_EGG_CACHE'] = '/tmp/python-eggs'

# setting up logging
ini_file = '/etc/mozilla-services/trunion/production.ini'
ini_file = os.environ.get('TRUNION_INI', ini_file)
try:
    fileConfig(ini_file)
except NoSectionError:
    pass

# running the app using Paste
from paste.deploy import loadapp

application = loadapp('config:%s' % ini_file)
