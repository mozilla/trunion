""" Setup file.
"""
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()


setup(name='trunion',
    version=0.1,
    description="Application receipt certifier and verifier",
    long_description=README,
    classifiers=[
        "Programming Language :: Python",
        "Framework :: Pylons",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application"
    ],
    keywords="web services",
    author='Ryan Tilder',
    author_email="Ryan Tilder -at- example.com",
    url="http://example.com",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=['cornice', 'PasteScript'],
    entry_points = """\
    [paste.app_factory]
    main = trunion:main
    """,
    paster_plugins=['pyramid'],
)
