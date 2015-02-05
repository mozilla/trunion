APPNAME = trunion
DEPS =
VIRTUAL_ENV ?= $(shell pwd)
BIN = $(VIRTUAL_ENV)/bin
VIRTUALENV = virtualenv
NOSE = $(BIN)/nosetests -s --with-xunit
TESTS = $(APPNAME)/tests
PYTHON = $(BIN)/python
BUILDAPP = $(BIN)/buildapp
BUILDRPMS = $(BIN)/buildrpms
PYPI = http://pypi.python.org/simple
PYPIOPTIONS = -i $(PYPI)
PYPI2 = http://pypi.python.org/packages
BUILD_TMP = /tmp/trunion-build.${USER}
DOTCHANNEL := $(wildcard .channel)
ifeq ($(strip $(DOTCHANNEL)),)
	CHANNEL = dev
	RPM_CHANNEL = prod
else
	CHANNEL = `cat .channel`
	RPM_CHANNEL = `cat .channel`
endif
INSTALL = $(BIN)/pip install
PIP_DOWNLOAD_CACHE ?= /tmp/pip_cache
INSTALLOPTIONS = --download-cache $(PIP_DOWNLOAD_CACHE) -U -i $(PYPI)
RPMDIR= $(CURDIR)/rpms

ifdef PYPIEXTRAS
	PYPIOPTIONS += -e $(PYPIEXTRAS)
	INSTALLOPTIONS += -f $(PYPIEXTRAS)
endif

ifdef PYPISTRICT
	PYPIOPTIONS += -s
	ifdef PYPIEXTRAS
		HOST = `python -c "import urlparse; print urlparse.urlparse('$(PYPI)')[1] + ',' + urlparse.urlparse('$(PYPIEXTRAS)')[1]"`

	else
		HOST = `python -c "import urlparse; print urlparse.urlparse('$(PYPI)')[1]"`
	endif

endif

INSTALL += $(INSTALLOPTIONS)


.PHONY: all build test build_rpms mach

all:	build

build:
	$(VIRTUALENV) --no-site-packages .
	$(INSTALL) MoPyTools
	$(INSTALL) nose
	$(INSTALL) WebTest
	$(BUILDAPP) -c $(CHANNEL) $(PYPIOPTIONS) $(DEPS)

update:
	$(BUILDAPP) -c $(CHANNEL) $(PYPIOPTIONS) $(DEPS)

test:
	$(NOSE) $(APPNAME)

build_rpms:
	rm -rf rpms/
	mkdir -p rpms ${BUILD_TMP}
	$(BUILDRPMS) -c $(RPM_CHANNEL) $(DEPS)
	cd ${BUILD_TMP} && wget $(PYPI2)/source/M/M2Crypto/M2Crypto-0.21.1.tar.gz#md5=f93d8462ff7646397a9f77a2fe602d17
	cd ${BUILD_TMP} && tar -xzvf M2Crypto-0.21.1.tar.gz && cd M2Crypto-0.21.1 && sed -i -e 's/opensslconf\./opensslconf-x86_64\./' SWIG/_ec.i && sed -i -e 's/opensslconf\./opensslconf-x86_64\./' SWIG/_evp.i && SWIG_FEATURES=-cpperraswarn $(PYTHON) setup.py --command-packages=pypi2rpm.command bdist_rpm2 --binary-only --dist-dir=$(RPMDIR) --name=python26-m2crypto
	rm -rf ${BUILD_TMP}/M2Crypto*

mach: build build_rpms
	mach clean
	mach yum install python26 python26-setuptools
	cd rpms; wget http://mrepo.mozilla.org/mrepo/5-x86_64/RPMS.mozilla-services/gunicorn-0.11.2-1moz.x86_64.rpm
	cd rpms; wget http://mrepo.mozilla.org/mrepo/5-x86_64/RPMS.mozilla/nginx-0.7.65-4.x86_64.rpm
	mach yum install rpms/*
	mach chroot python2.6 -m trunion.run
