Documentation
=============

See https://wiki.mozilla.org/Apps/WebApplicationReceipt/SigningService


Dev and testing
---------------

Create a virtualenv of your choosing and activate it::

    virtualenv trunion
    source trunion/bin/activate

Or using virtualenvwrapper::

    mkvirtualenv trunion


Install the dependencies::

    pip install -r dev-reqs.txt


Run tests::

    make test
