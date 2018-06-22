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
# How to use this file:
# For normal use, just import the class "Archivehandle". Check class description
# for more information how to use the class.

import sys
import zipfile
import tarfile
import re

STATUS = "available: zip, tar"
ENABLED = True
RARFILE_AVAILABLE = 0
try:
    import rarfile
    RARFILE_AVAILABLE = 1
    STATUS += ", rar"
except (ImportError, OSError):
    pass


SEVENZIP_AVAILABLE = 0
try:
    import py7zlib # installed via pylzma library
    SEVENZIP_AVAILABLE = 1
    STATUS += ", 7z"
except (ImportError, OSError):
    pass


#-------------#
#- Interface -#
#-------------#
class Archive_int(object):
    """
    Archive_int is the interface for the archive handle implementations
    """

    def __init__(self, filedescriptor):
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

    def filesize(self, path):
        """get extracted file size

        Args:
            path (str): is the filename in the archive as returned by namelist
        Raises:
            NotImplemented because this routine has to be implemented by classes deriving
        """
        raise NotImplemented

    def extract(self, path, archivecontentmaxsize):
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
    def __init__(self,filedescriptor):
        super(Archive_zip, self).__init__(filedescriptor)

        if sys.version_info < (2, 7):
            try:
                # As far as I understand this fix is needed for bytes like objects (io.BytesIO).
                # The routine will fail with AttributeError or IOError or something else for
                # other inputs. For example in the unittests, a filename is sent in which does
                # not have read/truncate/... attributes.
                filedescriptor = Archive_zip.fix_python26_zipfile_bug(filedescriptor)
            except Exception:
                pass
        self._handle = zipfile.ZipFile(filedescriptor)

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
            zipFileContainer (file-like object):

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
        if archivecontentmaxsize is not None and self.filesize(path) > archivecontentmaxsize:
            return None
        return self._handle.read(path)

    def filesize(self, path):
        """get extracted file size

        Args:
            path (str): is the filename in the archive as returned by namelist
        Returns:
            (int) file size in bytes
        """
        return self._handle.getinfo(path).file_size

class Archive_rar(Archive_int):
    def __init__(self, filedescriptor):
        super(Archive_rar, self).__init__(filedescriptor)
        self._handle = rarfile.RarFile(filedescriptor)

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
        if archivecontentmaxsize is not None and self.filesize(path) > archivecontentmaxsize:
            return None
        return self._handle.read(path)

    def filesize(self, path):
        """get extracted file size

        Args:
            path (str): is the filename in the archive as returned by namelist
        Returns:
            (int) file size in bytes
        """
        return self._handle.getinfo(path).file_size

class Archive_tar(Archive_int):
    def __init__(self, filedescriptor):
        super(Archive_tar, self).__init__(filedescriptor)
        try:
            self._handle = tarfile.open(fileobj=filedescriptor)
        except AttributeError:
            self._handle = tarfile.open(filedescriptor)

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
        if archivecontentmaxsize is not None and self.filesize(path) > archivecontentmaxsize:
            return None

        arinfo = self._handle.getmember(path)
        if not arinfo.isfile():
            return None
        x = self._handle.extractfile(path)
        extracted = x.read()
        x.close()
        return extracted

    def filesize(self, path):
        """get extracted file size

        Args:
            path (str): is the filename in the archive as returned by namelist
        Returns:
            (int) file size in bytes
        """
        arinfo = self._handle.getmember(path)
        return arinfo.size

class Archive_7z(Archive_int):
    def __init__(self, filedescriptor):
        super(Archive_7z, self).__init__(filedescriptor)
        self._fdescriptor = None
        try:
            self._handle = py7zlib.Archive7z(filedescriptor)
        except AttributeError:
            self._fdescriptor = open(filedescriptor,'rb')
            self._handle = py7zlib.Archive7z(self._fdescriptor)

    def namelist(self):
        """ Get archive file list

        Returns:
            (list) Returns a list of file paths within the archive
        """
        return self._handle.getnames()


    def extract(self, path, archivecontentmaxsize):
        if archivecontentmaxsize is not None and self.filesize(path) > archivecontentmaxsize:
            return None
        arinfo = self._handle.getmember(path)
        return arinfo.read()

    def filesize(self, path):
        """get extracted file size

        Args:
            path (str): is the filename in the archive as returned by namelist
        Returns:
            (int) file size in bytes
        """
        arinfo = self._handle.getmember(path)
        return arinfo.size

    def close(self):
        """
        Close handle
        """
        super(Archive_7z, self).close()
        if self._fdescriptor is not None:
            try:
                self._fdescriptor.close()
            except Exception:
                pass
        self._fdescriptor = None

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

    (1) Using Archivehandle go get information about available archive handles:

    Examples:
        Archivehandle.avail('tar') # check if tar archives can be handled
        Archivehandle.avail('zip') # check if zip archives can be handled
        Archivehandle.avail_archives_list # returns a list of archives that can be handled, for example
                                          # [ "rar", "zip" ]
        Archivehandle.avail_archive_extensions_list # returns a list of archive extensions (sorted by extension length)
                                                    # for example ['tar.bz2', 'tar.gz', 'tar', 'zip', 'tgz']
        Archivehandle.avail_archive_ctypes_list # returns a list of mnail content type regex expressions,
                                                # for example ['^application\\/x-tar', '^application\\/zip',
                                                               '^application\\/x-bzip2', '^application\\/x-gzip']

    (2) Use Archivehandle to create a handle to work with an archive:

    Example:
        handle = Archivehandle('zip','test.zip') # get a handle
        files = handle.namelist()        # get a list of files contained in archive
        firstfileContent = handle.extract(files[0],500000) # extract first file if smaller than 0.5 MB
        print(firstfileContent)          # print content of first file extracted
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

    # avail_archive_ctypes_list is a list of available ctypes based on available implementations
    _avail_archive_ctypes_list = None

    # avail_archive_ctypes is a dict, set automatically based on available implementations
    # key:   regex matching content type as returned by file magic (see filetype.py)
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
            newList = sorted(cls.avail_archive_extensions.keys(), key=lambda x: len(x), reverse=True)
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
    def avail_archive_ctypes_list(cls):
        # first time this list has to be created based on what's available
        if cls._avail_archive_ctypes_list is None:
            tlist = []
            for ctype,atype in iter(Archivehandle.avail_archive_ctypes.items()):
                if Archivehandle.avail(atype):
                    tlist.append(ctype)
            cls._avail_archive_ctypes_list = tlist
        return cls._avail_archive_ctypes_list

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

    @staticmethod
    def archive_type_from_content_type(content_type, all_impl = False, custom_ctypes_dict = None):
        """
        Return the corresponding archive type if the content type matches a regex , None otherwise

        Args:
            content_type (str): content type string
            all_impl (bool): check all implementations, not only the ones available
            custom_ctypes_dict (dict): dict with custom mapping (key: regex matching content type as returned by file magic, value: archive type)

        Returns:
            (str or None) archive type

        """

        if content_type is None:
            return None

        archive_type = None
        if all_impl:
            ctypes2check = Archivehandle.implemented_archive_ctypes
        elif custom_ctypes_dict is not None:
            ctypes2check = custom_ctypes_dict
        else:
            ctypes2check = Archivehandle.avail_archive_ctypes

        for regex, atype in iter(ctypes2check.items()):
            if re.match(regex, content_type, re.I):
                archive_type = atype
                break

        return archive_type

    @staticmethod
    def archive_type_from_extension(att_name, all_impl = False, custom_extensions_dict = None):
        """
        Return the corresponding archive type if the extension matches regex , None otherwise

        Args:
            att_name (str): filename
            all_impl (bool): check all implementations, not only the ones available
            custom_ctypes_dict (dict): dict with custom mapping (key: regex matching content type as returned by file magic, value: archive type)

        Returns:
            (str or None) archive type

        """
        if att_name is None:
            return None

        if all_impl:
            sorted_ext_dict = Archivehandle.implemented_archive_extensions
            # sort by length, so tar.gz is checked before .gz
            sorted_ext_list = sorted(sorted_ext_dict.keys(), key=lambda x: len(x), reverse=True)
        elif custom_extensions_dict is not None:
            sorted_ext_dict = custom_extensions_dict
            # sort by length, so tar.gz is checked before .gz
            sorted_ext_list = sorted(sorted_ext_dict.keys(), key=lambda x: len(x), reverse=True)
        else:
            sorted_ext_dict = Archivehandle.avail_archive_extensions
            # this list is already sorted
            sorted_ext_list = Archivehandle.avail_archive_extensions_list

        archive_type = None
        for arext in sorted_ext_list:
            if att_name.lower().endswith('.%s' % arext):
                archive_type = sorted_ext_dict[arext]
                break
        return archive_type

    def __new__(cls,archive_type,filedescriptor):
        """
        Factory method that will produce and return the correct implementation depending
        on the archive type

        Args:
            archive_type (str): archive type ('zip','rar','tar','7z')
            filedescriptor (): file-like object (io.BytesIO) or path-like object (str or bytes with filename including path)
        """

        assert Archivehandle.impl(archive_type), "Archive type %s not in list of supported types: %s" % (archive_type, ",".join(Archivehandle.archive_impl.keys()))
        assert Archivehandle.avail(archive_type), "Archive type %s not in list of available types: %s" % (archive_type, ",".join(Archivehandle.avail_archives_list))

        return Archivehandle.archive_impl[archive_type](filedescriptor)

