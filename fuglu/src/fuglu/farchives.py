# -*- coding: UTF-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# This content has been extracted from attachment.py and refactored
#

import sys
import zipfile
import tarfile

RARFILE_AVAILABLE = 0
try:
    import rarfile
    RARFILE_AVAILABLE = 1
except (ImportError, OSError):
    pass


SEVENZIP_AVAILABLE = 0
try:
    import py7zlib # installed via pylzma library
    SEVENZIP_AVAILABLE = 1
except (ImportError, OSError):
    pass


#-------------#
#- Interface -#
#-------------#
class Archive_int(object):
    """
    Archive_int is the interface for the archive handle implementations
    """

    def __init__(self, filestream):
        self._handle = None

    def close(self):
        try:
            self._handle.close()
        except AttributeError:
            pass

    def namelist(self):
        """ Get archive file list

        Returns:
            (list) Returns a list of file paths within the archive
        """
        return []

    def extract(handle, path, archivecontentmaxsize):
        """extract a file from the archive into memory

        Args:
            path (str): is the filename in the archive as returned by namelist
            archivecontentmaxsize (int): maximum file size allowed to be extracted from archive
        Returns:
            (bytes or None) returns the file content or None if the file would be larger than the setting archivecontentmaxsize

        """
        return None

#---------------------------#
#- Archive implementations -#
#---------------------------#
# Don't forget to add new implementations to the dict "archive_impl" and "archive_avail"
# below the implementations in class Archivehandle

class Archive_zip(Archive_int):
    def __init__(self,filestream):
        super(Archive_zip, self).__init__(filestream)

        if sys.version_info < (2, 7):
            filestream = Archive_zip.fix_python26_zipfile_bug(filestream)
        self._handle = zipfile.ZipFile(filestream)

    @staticmethod
    def fix_python26_zipfile_bug(zipFileContainer):
        """

        "http://stackoverflow.com/questions/3083235/unzipping-file-results-in-badzipfile-file-is-not-a-zip-file/21996397#21996397"

        HACK: See http://bugs.python.org/issue10694
        The zip file generated is correct, but because of extra data after the 'central directory' section,
        Some version of python (and some zip applications) can't read the file. By removing the extra data,
        we ensure that all applications can read the zip without issue.
        The ZIP format: http://www.pkware.com/documents/APPNOTE/APPNOTE-6.3.0.TXT
        Finding the end of the central directory:
          http://stackoverflow.com/questions/8593904/how-to-find-the-position-of-central-directory-in-a-zip-file
          http://stackoverflow.com/questions/20276105/why-cant-python-execute-a-zip-archive-passed-via-stdin
        This second link is only loosely related, but echos the first,
        "processing a ZIP archive often requires backwards seeking"

        Args:
            zipFileContainer ():

        Returns:
            modified zip-file bytes content

        """

        content = zipFileContainer.read()
        # reverse find: this string of bytes is the end of the zip's central
        # directory.
        pos = content.rfind('\x50\x4b\x05\x06')
        if pos > 0:
            # +20: see section V.I in 'ZIP format' link above.
            zipFileContainer.seek(pos + 20)
            zipFileContainer.truncate()
            # Zip file comment length: 0 byte length; tell zip applications to
            # stop reading.
            zipFileContainer.write('\x00\x00')
            zipFileContainer.seek(0)
        return zipFileContainer

    def namelist(self):
        """ Get archive file list

        Returns:
            (list) Returns a list of file paths within the archive
        """
        return self._handle.namelist()

    def extract(self, path, archivecontentmaxsize):
        """extract a file from the archive into memory

        Args:
            path (str): is the filename in the archive as returned by namelist
            archivecontentmaxsize (int): maximum file size allowed to be extracted from archive
        Returns:
            (bytes or None) returns the file content or None if the file would be larger than the setting archivecontentmaxsize

        """
        arinfo = self._handle.getinfo(path)
        if arinfo.file_size > archivecontentmaxsize:
            return None
        return self._handle.read(path)

class Archive_rar(Archive_int):
    def __init__(self, filestream):
        super(Archive_rar, self).__init__(filestream)
        self._handle = rarfile.RarFile(filestream)

    def namelist(self):
        """ Get archive file list

        Returns:
            (list) Returns a list of file paths within the archive
        """
        return self._handle.namelist()

    def extract(self, path, archivecontentmaxsize):
        """extract a file from the archive into memory

        Args:
            path (str): is the filename in the archive as returned by namelist
            archivecontentmaxsize (int): maximum file size allowed to be extracted from archive
        Returns:
            (bytes or None) returns the file content or None if the file would be larger than the setting archivecontentmaxsize

        """
        arinfo = self._handle.getinfo(path)
        if arinfo.file_size > archivecontentmaxsize:
            return None
        return self._handle.read(path)

class Archive_tar(Archive_int):
    def __init__(self, filestream):
        super(Archive_tar, self).__init__(filestream)
        self._handle = tarfile.open(fileobj=filestream)

    def namelist(self):
        """ Get archive file list

        Returns:
            (list) Returns a list of file paths within the archive
        """
        return self._handle.getnames()

    def extract(self, path, archivecontentmaxsize):
        """extract a file from the archive into memory

        Args:
            path (str): is the filename in the archive as returned by namelist
            archivecontentmaxsize (int): maximum file size allowed to be extracted from archive
        Returns:
            (bytes or None) returns the file content or None if the file would be larger than the setting archivecontentmaxsize

        """
        arinfo = self._handle.getmember(path)
        if arinfo.size > archivecontentmaxsize or not arinfo.isfile():
            return None
        x = self._handle.extractfile(path)
        extracted = x.read()
        x.close()
        return extracted

class Archive_7z(Archive_int):
    def __init__(self, filestream):
        super(Archive_7z, self).__init__(filestream)
        self._handle = py7zlib.Archive7z(filestream)

    def namelist(self):
        """ Get archive file list

        Returns:
            (list) Returns a list of file paths within the archive
        """
        return self._handle.getnames()

    def extract(self, path, archivecontentmaxsize):
        arinfo = self._handle.getmember(path)
        if arinfo.size > archivecontentmaxsize:
            return None
        return arinfo.read()

#--                  --#
#- use class property -#
#--                  --#
# inspired by:
# https://stackoverflow.com/questions/128573/using-property-on-classmethods
# Working for static getter implementation in Py2 and Py3
class classproperty(property):
    def __get__(self, obj, objtype=None):
        return super(classproperty, self).__get__(objtype)

#--------------------------------------------------------------------------#
#- The pubic available factory class to produce the archive handler class -#
#--------------------------------------------------------------------------#
class Archivehandle(object):
    """
    Archivehandle is the actually the factory for the archive handle implementations.
    Besides being the factory, Archivehandle provides also dicts and lists of implemented
    and available archives based on different keys (for example file extension).
    """

    # Dict mapping implementations to archive type string
    archive_impl = {"zip": Archive_zip,
                    "rar": Archive_rar,
                    "tar": Archive_tar,
                    "7z" : Archive_7z}

    # Dict storing if archive type is available
    archive_avail= {"zip": True,
                    "rar": (RARFILE_AVAILABLE > 0),
                    "tar": True,
                    "7z" : (SEVENZIP_AVAILABLE > 0)}


    # key: regex matching content type as returned by file magic, value: archive type
    implemented_archive_ctypes = {
        '^application\/zip': 'zip',
        '^application\/x-tar': 'tar',
        '^application\/x-gzip': 'tar',
        '^application\/x-bzip2': 'tar',
        '^application\/x-rar': 'rar',         # available only if RARFILE_AVAILABLE > 0
        '^application\/x-7z-compressed': '7z' # available only if SEVENZIP_AVAILABLE > 0
    }


    # key: file ending, value: archive type
    implemented_archive_extensions = {
        'zip': 'zip',
        'z': 'zip',
        'tar': 'tar',
        'tar.gz': 'tar',
        'tgz': 'tar',
        'tar.bz2': 'tar',
        'rar': 'rar', # available only if RARFILE_AVAILABLE > 0
        '7z': '7z',   # available only if SEVENZIP_AVAILABLE > 0
    }

    #--
    # dicts and lists containing information about available
    # archives are setup automatically (see below in metaclass)
    #--

    # "avail_archives_list" is a list of available archives based on available implementations
    _avail_archives_list = None

    # avail_archive_ctypes is a dict, set automatically based on available implementations
    # key:   regex matching content type as returned by file magic (see filetypemagic.py)
    # value: archive type
    _avail_archive_ctypes = None

    # "avail_archive_extensions_list" is a list of available filetype extensions.
    # sorted by length, so tar.gz is checked before .gz
    _avail_archive_extensions_list = None

    # "avail_archive_extensions" dict with available archive types for file extensions
    # key: file ending
    # value: archive type
    _avail_archive_extensions = None

    @classproperty
    def avail_archive_extensions_list(cls):
        # first time this list has to be created based on what's available
        if cls._avail_archive_extensions_list is None:
            # sort by length, so tar.gz is checked before .gz
            newList = sorted(cls._supported_archive_extensions.keys(), key=lambda x: len(x), reverse=True)
            cls._avail_archive_extensions_list = newList
        return cls._avail_archive_extensions_list

    @classproperty
    def avail_archives_list(cls):
        # first time this list has to be created based on what's available
        if cls._avail_archives_list is None:
            tlist = []
            for atype,available in iter(Archivehandle.archive_avail.items()):
                if available:
                    tlist.append(atype)
            cls._avail_archives_list = tlist
        return cls._avail_archives_list


    @classproperty
    def avail_archive_ctypes(cls):
        # first time this dict has to be created based on what's available
        if cls._avail_archive_ctypes is None:
            newDict = {}
            for regex,atype in iter(Archivehandle.implemented_archive_ctypes.items()):
                if Archivehandle.avail(atype):
                    newDict[regex] = atype
            cls._avail_archive_ctypes = newDict

        return cls._avail_archive_ctypes

    @classproperty
    def avail_archive_extensions(cls):
        # first time this dict has to be created based on what's available
        if cls._avail_archive_extensions is None:
            newDict = {}
            for regex,atype in iter(Archivehandle.implemented_archive_extensions.items()):
                if Archivehandle.avail(atype):
                    newDict[regex] = atype
            cls._avail_archive_extensions = newDict

        return cls._avail_archive_extensions


    @staticmethod
    def impl(archive_type):
        """
        Checks if archive type is implemented
        Args:
            archive_type (Str): Archive type to be checked, for example ('zip','rar','tar','7z')

        Returns:
            True if there is an implementation

        """
        return archive_type in Archivehandle.archive_impl

    @staticmethod
    def avail(archive_type):
        """
        Checks if archive type is available
        Args:
            archive_type (Str): Archive type to be checked, for example ('zip','rar','tar','7z')

        Returns:
            True if archive type is available

        """
        if not Archivehandle.impl(archive_type):
            return False
        return Archivehandle.archive_avail[archive_type]

    def __new__(cls,archive_type,filestream):
        """
        Factory method that will produce and return the correct implementation depending
        on the archive type

        Args:
            archive_type (str): archive type ('zip','rar','tar','7z')
            filestream (bytes): created for example by "open('filename')" or in-memory by io.BytesIO
        """

        assert Archivehandle.impl(archive_type), "Archive type %s not in list of supported types: %s" % (archive_type, ",".join(Archivehandle.archive_impl.keys()))
        assert Archivehandle.avail(archive_type), "Archive type %s not in list of available types: %s" % (archive_type, ",".join(Archivehandle.avail_archives_list))

        return Archivehandle.archive_impl[archive_type](filestream)

