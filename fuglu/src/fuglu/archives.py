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
# Dont't forget to add new implementations to the dict "archive_impl"
# below the implementations

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

#-------------------------------------------------------#
#- Dict mapping implementations to archive type string -#
#-------------------------------------------------------#
# Note this has to be after the actual impelementations of Archive_*
archive_impl = {"zip": Archive_zip,
                "rar": Archive_rar,
                "tar": Archive_tar,
                "7z" : Archive_7z}

#--------------------------------------------------------------------------#
#- The pubic available factory class to produce the archive handler class -#
#--------------------------------------------------------------------------#
class Archivehandle(object):
    """
    Archivehandle is the actually the factory for the archive handle implementations
    """

    def __new__(cls,archive_type,filestream):
        """
        Factory method that will prduce and return the correct implementation depending
        on the archive type

        Args:
            archive_type (str): archive type ('zip','rar','tar','7z')
            filestream (bytes): created for example by "open('filename')" or in-memory by io.BytesIO
        """

        assert archive_type in archive_impl, "Archive type %s not in list of supported types: %s" % (archive_type, ",".join(archive_impl.keys()))

        return archive_impl[archive_type](filestream)
