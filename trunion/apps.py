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
import re
import zipfile

headers_re = re.compile(
    r"""^((?:Manifest|Signature)-Version
          |Name
          |Digest-Algorithms
          |(?:MD5|SHA1)-Digest)
          \s*:\s*(.*)""", re.X | re.I)


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
    payload = 'manifest'

    @classmethod
    def parse(klass, buf):
        #payload = None
        #version = None
        if hasattr(buf, 'readlines'):
            fest = buf
        else:
            fest = StringIO(buf)
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
            elif 'name' == header:
                if item is not None:
                    items.append(item)
                item = Section(value)
                continue
            elif 'digest-algorithms' == header:
                item.algos = tuple(re.split('\s*', value.lower()))
                continue
            elif '-digest' == header[-7:]:
                item.digests[header[:-7]] = b64decode(value)
                continue
        return klass(items)

    def __str__(self):
        header = "%s-Version: %s\n\n" % (self.payload.title(), self.version)
        return header + "\n".join([str(i) for i in self])


class Signature(Manifest):
    payload = 'signature'


class JarExtractor(object):
    """
    """

    def __init__(self, path):
        """
        """
        self._digests = []

        try:
            z = zipfile.ZipFile(path, 'r')
        except IOError, e:
            #log it
            raise e

        for f in z.filelist:
            digests = self._digest(z.read(f.filename))
            item = Section(f.filename, algos=tuple(digests.keys()),
                           digests=digests)
            self._digests.append(item)
        z.close()

    def _digest(self, data):
        md5 = hashlib.md5()
        md5.update(data)
        sha1 = hashlib.sha1()
        sha1.update(data)
        return {'md5': md5.digest(), 'sha1': sha1.digest()}

    def _sign(self, item):
        digests = self._digest(str(item))
        return Section(item.name, algos=tuple(digests.keys()),
                       digests=digests)

    @property
    def manifest(self):
        return Manifest(self._digests)

    @property
    def signatures(self):
        # The META-INF/zigbert.sf file contains hashes of the individual
        # sections of the the META-INF/manifest.mf file.  So we generate that
        # here
        return Manifest([self._sign(f) for f in self._digests])


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
