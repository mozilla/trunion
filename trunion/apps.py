# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

from base64 import b64encode, b64decode
from cStringIO import StringIO
import hashlib
from M2Crypto.BIO import MemoryBuffer
from M2Crypto.SMIME import SMIME, PKCS7_DETACHED, PKCS7_BINARY
import os.path
import re
import zipfile

headers_re = re.compile(
    r"""^((?:Manifest|Signature)-Version
          |Name
          |Digest-Algorithms
          |(?:MD5|SHA1)-Digest(?:-Manifest))
          \s*:\s*(.*)""", re.X | re.I)
directory_re = re.compile(r"[\\/]$")


def file_key(zinfo):
    '''
    Sort keys for xpi files
    @param name: name of the file to generate the sort key from
    '''
    # Copied from xpisign.py's api.py and tweaked
    name = zinfo.filename
    prio = 4
    if name == 'install.rdf':
        prio = 1
    elif name in ["chrome.manifest", "icon.png", "icon64.png"]:
        prio = 2
    elif name in ["MPL", "GPL", "LGPL", "COPYING", "LICENSE", "license.txt"]:
        prio = 5
    parts = [prio] + list(os.path.split(name.lower()))
    return "%d-%s-%s" % tuple(parts)


def _digest(data):
    md5 = hashlib.md5()
    md5.update(data)
    sha1 = hashlib.sha1()
    sha1.update(data)
    return {'md5': md5.digest(), 'sha1': sha1.digest()}


class Section(object):
    __slots__ = ('name', 'algos', 'digests')

    def __init__(self, name, algos=('md5', 'sha1'), digests={}):
        self.name = name
        self.algos = algos
        self.digests = digests

    def __str__(self):
        # Important thing to note: placement of newlines in these strings is
        # sensitive and should not be changed without reading through
        # http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#JAR%20Manifest
        # thoroughly.
        algos = ''
        order = self.digests.keys()
        order.sort()
        for algo in order:
            algos += " %s" % algo.upper()
        entry = "Name: %s\n" % self.name
        entry += "Digest-Algorithms:%s\n" % algos
        for algo in order:
            entry += "%s-Digest: %s\n" % (algo.upper(),
                                          b64encode(self.digests[algo]))
        return entry


class Manifest(list):
    version = '1.0'

    def __init__(self, *args, **kwargs):
        super(Manifest, self).__init__(*args)
        for k, v in kwargs.iteritems():
            setattr(self, k, v)

    @classmethod
    def parse(klass, buf):
        #version = None
        if hasattr(buf, 'readlines'):
            fest = buf
        else:
            fest = StringIO(buf)
        kwargs = {}
        items = []
        item = None
        for line in fest.readlines():
            line = line.strip()
            if line == '':
                continue
            match = headers_re.match(line)
            header = match.group(1).lower()
            value = match.group(2)
            if '-version' == header[-8:]:
                # Not doing anything with these at the moment
                #payload = header[:-8]
                #version = value.strip()
                pass
            elif '-digest-manifest' == header[-16:]:
                if 'digest_manifests' not in kwargs:
                    kwargs['digest_manifests'] = {}
                kwargs['digest_manifests'][header[:-16]] = b64decode(value)
            elif 'name' == header:
                if item is not None:
                    items.append(item)
                if directory_re.search(value):
                    continue
                item = Section(value)
                continue
            elif 'digest-algorithms' == header:
                item.algos = tuple(re.split('\s*', value.lower()))
                continue
            elif '-digest' == header[-7:]:
                item.digests[header[:-7]] = b64decode(value)
                continue
        if len(kwargs):
            return klass(items, **kwargs)
        return klass(items)

    @property
    def header(self):
        return "%s-Version: %s" % (type(self).__name__.title(),
                                       self.version)

    @property
    def body(self):
        return "\n".join([str(i) for i in self])

    def __str__(self):
        return "\n".join([self.header, "", self.body])


class Signature(Manifest):
    omit_individual_sections = True
    digest_manifests = {}

    @property
    def digest_manifest(self):
        return ["%s-Digest-Manifest: %s" % (i[0].upper(), b64encode(i[1]))
                for i in sorted(self.digest_manifests.iteritems())]

    @property
    def header(self):
        header = super(Signature, self).header
        return "\n".join([header, ] + self.digest_manifest)

    # So we can omit the individual signature sections
    def __str__(self):
        if self.omit_individual_sections:
            return str(self.header)
        return super(Signature, self).__str__()


class JarExtractor(object):
    """
    Walks an archive, creating manifest.mf and signature.sf contents as it goes

    Can also generate a new signed archive, if given a PKCS#7 signature
    """

    def __init__(self, path, outpath=None, omit_signature_sections=False):
        """
        """
        self.inpath = path
        self.outpath = outpath
        self._digests = []
        self.omit_sections = omit_signature_sections

        self._manifest = None
        self._sig = None

        with zipfile.ZipFile(self.inpath, 'r') as zin:
            for f in sorted(zin.filelist, key=file_key):
                if directory_re.search(f.filename):
                    continue
                digests = _digest(zin.read(f.filename))
                item = Section(f.filename, algos=tuple(digests.keys()),
                               digests=digests)
                self._digests.append(item)

    def _sign(self, item):
        digests = _digest(str(item))
        return Section(item.name, algos=tuple(digests.keys()),
                       digests=digests)

    @property
    def manifest(self):
        if not self._manifest:
            self._manifest = Manifest(self._digests)
        return self._manifest

    @property
    def signatures(self):
        # The META-INF/zigbert.sf file contains hashes of the individual
        # sections of the the META-INF/manifest.mf file.  So we generate that
        # here
        if not self._sig:
            self._sig = Signature([self._sign(f) for f in self._digests],
                                  digest_manifests=_digest(str(self.manifest)),
                                  omit_individual_sections=self.omit_sections)
        return self._sig

    @property
    def signature(self):
        # Returns only the x-Digest-Manifest signature and omits the individual
        # section signatures
        return self.signatures.header

    def make_signed(self, signature, outpath=None):
        if self.outpath is None and outpath is None:
            raise IOError("No output file specified")
        with zipfile.ZipFile(self.inpath, 'r') as zin:
            with zipfile.ZipFile(outpath, 'w', zipfile.ZIP_DEFLATED) as zout:
                # zigbert.rsa *MUST* be the first file in the archive to take
                # advantage of Firefox's optimized downloading of XPIs
                zout.writestr("META-INF/zigbert.rsa", signature)
                for f in sorted(zin.namelist()):
                    zout.writestr(f.filename, zout.read(f.filename))
                zout.writestr("META-INF/manifest.mf", str(self.manifest))
                zout.writestr("META-INF/zigbert.sf", str(self.signatures))


class JarSigner(object):

    def __init__(self, privkey, certchain):
        self.privkey = privkey
        self.chain = certchain
        self.smime = SMIME()
        # We short circuit the key loading functions in the SMIME class
        self.smime.pkey = self.privkey
        self.smime.set_x509_stack(self.chain)

    def sign(self, data):
        # XPI signing is JAR signing which uses PKCS7 detached signatures
        pkcs7 = self.smime.sign(MemoryBuffer(data),
                                PKCS7_DETACHED | PKCS7_BINARY)
        pkcs7_buffer = MemoryBuffer()
        pkcs7.write_der(pkcs7_buffer)
        return pkcs7
