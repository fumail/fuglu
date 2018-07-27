# -*- coding: utf-8 -*-
#   Copyright 2009-2018 Fumail Project
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
#
#

import mimetypes
import threading
from email.header import decode_header
import email
import sys
import logging
from fuglu.extensions.filearchives import Archivehandle
from fuglu.extensions.filetype import filetype_handler
from fuglu.caching import smart_cached_property, smart_cached_memberfunc, Cachelimits
from fuglu.stringencode import force_uString
from io import BytesIO

# workarounds for mimetypes
# - always takes .ksh for text/plain
# - python3 takes .exe for application/octet-stream which is often used for content types
#   unknwon to the creating MUA (e.g. pdf files are often octet-stream)
MIMETYPE_EXT_OVERRIDES = {
    'text/plain': 'txt',
    'application/octet-stream': None,
}


class Mailattachment(threading.local, Cachelimits):
    """
    Mail attachment object or a file contained in the attachment.
    """
    objectCounter = 0
    def __init__(self, buffer, filename, mgr, filesize=None, in_obj=None, contenttype_mime=None, maintype_mime=None,
                 subtype_mime=None, ismultipart_mime=None, content_charset_mime=None):
        """
        Constructor
        Args:
            buffer (bytes): buffer containing attachment source
            filename (str): filename of current attachment object
            filesize (size): file size in bytes
            mgr (Mailattachment_mgr): Mail attachment manager
            in_obj (Mailattachment): "Father" Mailattachment object (if existing), the archive containing the current object
            contenttype_mime (str): The contenttype as defined in the mail attachment, only available for direct mail attachments
            maintype_mime (str): The main contenttype as defined in the mail attachment, only available for direct mail attachments
            subtype_mime (str): The sub-contenttype as defined in the mail attachment, only available for direct mail attachments
            ismultipart_mime (str): multipart as defined in the mail attachment, only available for direct mail attachments
            content_charset_mime (str): The characterset as defined in the mail attachment, only available for direct mail attachments
        """
        super(Mailattachment, self).__init__()
        self.filename = filename
        self.filesize = filesize
        self.buffer = buffer
        self._buffer_archobj = {}
        self.in_obj = in_obj
        self.contenttype_mime     = contenttype_mime
        self.maintype_mime        = maintype_mime
        self.subtype_mime         = subtype_mime
        self.ismultipart_mime     = ismultipart_mime
        self.content_charset_mime = content_charset_mime
        self._mgr = mgr

        # try to increment object counter in manager for each object created.
        # this helps debugging and testing caching...
        try:
            self._mgr._increment_ma_objects()
        except AttributeError:
            pass

    def content_fname_check(self,maintype=None,ismultipart=None,subtype=None,contenttype=None,contenttype_start=None,
                            name_end=None,contenttype_contains=None,name_contains=None):
        """
        Test content or filename for options or a set of options. All inputs except 'ismultipart' allow
        simple strings, a list of strings or a tuple of strings as input.
        """
        try:
            if maintype is not None:
                if isinstance(maintype,(list,tuple)):
                    if not self.maintype_mime in maintype:
                        return False
                else:
                    if not self.maintype_mime == maintype:
                        return False

            if ismultipart is not None:
                if not self.ismultipart_mime == ismultipart:
                    return False

            if subtype is not None:
                if isinstance(subtype,(list,tuple)):
                    if not self.subtype_mime in subtype:
                        return False
                else:
                    if not self.subtype_mime == subtype:
                        return False

            if contenttype is not None:
                if isinstance(contenttype,(list,tuple)):
                    if not self.contenttype_mime in contenttype:
                        return False
                else:
                    if not self.contenttype_mime == contenttype:
                        return False

            if contenttype_start is not None:
                if isinstance(contenttype_start,list):
                    if not self.contenttype_mime.startswith(tuple(contenttype_start)):
                        return False
                else:
                    if not self.contenttype_mime.startswith(contenttype_start):
                        return False

            if name_end is not None:
                if isinstance(name_end,list):
                    if not self.filename.endswith(tuple(name_end)):
                        return False
                else:
                    if not self.filename.endswith(name_end):
                        return False

            if contenttype_contains is not None:
                if isinstance(contenttype_contains,(list,tuple)):
                    if not any((a in self.contenttype_mime for a in contenttype_contains)):
                        return False
                else:
                    if not contenttype_contains in self.contenttype_mime:
                        return False

            if name_contains is not None:
                if isinstance(name_contains,(list,tuple)):
                    if not any((a in self.filename for a in name_contains)):
                        return False
                else:
                    if not name_contains in self.filename:
                        return False
        except Exception:
            # for any exception happening return False
            return False

        return True

    @smart_cached_property(inputs=['buffer','in_obj','content_charset_mime'])
    def decoded_buffer_text(self):
        """
        (Cached Member Function)

        Try to decode the buffer.

        Internal member dependencies:
            - buffer (bytes): The buffer with the raw attachment content
            - in_obj (Mailattachment): Reference to parent if this object was extracted from an archive
            - content_charset_mime (string): charset if available or None

        Returns:
            unicode : the unicode string representing the buffer or an empty string on any error

        """

        # only for first level attachments
        if self.in_obj is None:
            try:
                # if charset is None or empty string use utf-8 as guess
                charset = self.content_charset_mime if self.content_charset_mime  else "utf-8"
                return force_uString(self.buffer,encodingGuess=charset)
            except Exception:
                pass

        return force_uString("")

    @smart_cached_property(inputs=['buffer'])
    def contenttype(self):
        """
        (Cached Property-Getter)

        Stores the content type of the file buffer using filetype_handler.

        Internal member dependencies:
            - buffer (bytes): File buffer
        Returns:
            (str): contenttype of file buffer
        """
        contenttype_magic = None
        if self.buffer is not None and filetype_handler.available():
            contenttype_magic = filetype_handler.get_buffertype(self.buffer)
        return contenttype_magic

    @smart_cached_property(inputs=['contenttype','filename'])
    def archive_type(self):
        """
        (Cached Property-Getter)

        Stores the archive type stored in this object.

        Internal member dependencies:
            - contenttype: File content type
            - filename: Filename (Extension might be used to detect archive type)

        Returns:
            (str): Archive type if object is an archive, None otherwise
        """

        self._arext = None

        # try guessing the archive type based on magic content type first
        archive_type = Archivehandle.archive_type_from_content_type(self.contenttype)

        # if it didn't work, try to guess by the filename extension, if it is enabled
        if archive_type is None:
            # sort by length, so tar.gz is checked before .gz
            for arext in Archivehandle.avail_archive_extensions_list:

                if self.filename.lower().endswith('.%s' % arext):
                    archive_type = Archivehandle.avail_archive_extensions[arext]
                    # store archive extension for internal use
                    self._arext = arext
                    break
        return archive_type

    @smart_cached_memberfunc(inputs=['archive_type'])
    def atype_fromext(self):
        """True if extension was used to determine archive type"""
        return self._arext

    @smart_cached_property(inputs=['archive_type'])
    def is_archive(self):
        """
        (Cached Property-Getter)

        Define if this object is an extractable archive or an ordinary file.

        Internal:
            - archive_type: Depends on the member variable 'archive_type'

        Returns:
            (bool): True for an archive that can be extracted
        """
        return self.archive_type is not None

    def get_fileslist(self, levelin, levelmax, maxsize_extract):
        """
        Get a list of files contained in this archive (recursively extracting archives)
        or the current filename if this is not an archive.

        Don't cache here, "fileslist_archive" is only available for
        archives. If this is put as dependency then there will be a
        archive handler applied on a non-archive which throws an
        exception

        IMPORTANT: If this is the maximal recursive level to check then only the filelist is
                   extracted from the archive but the actual archive files are NOT extracted.

        Args:
            levelin  (in): Current recursive level
            levelmax (in): Max recursive archive level up to which archives are extracted
            maxsize_extract (int): Maximum size that will be extracted to further go into archive

        Returns:
            (list[str]): List with filenames contained in this object or this object filename itself

        """
        if levelmax is None or levelin < levelmax:
            if self.is_archive:
                if levelmax is None or levelin + 1 < levelmax:
                    return self.get_fileslist_arch(levelin,levelmax,maxsize_extract)
                else:
                    return self.fileslist_archive

        return [self.filename]

    def get_objectlist(self,levelin, levelmax, maxsize_extract, noextractinfo=None):
        """
        Get a list of file objects contained in this archive (recursively extracting archives)
        or the current object if this is not an archive.

        Don't cache here, "fileslist_archive" is only available for
        archives. If this is put as dependency then there will be a
        archive handler applied on a non-archive which throws an
        exception

        IMPORTANT: This will extract the objects of (at least) the current recursive level.
                   Further extraction depends on the input recursion level.

        Args:
            levelin  (in): Current recursive level
            levelmax (in): Max recursive archive level up to which archives are extracted
            maxsize_extract (int): Maximum size that will be extracted to further go into archive

        Returns:
            (list[Mailattachment]): List with Mailattachment objects contained in this object of this object itself
        """
        if levelmax is None or levelin < levelmax:

            if self.is_archive:

                newlist = []
                if levelmax is None or levelin + 1 < levelmax:
                    for fname in self.fileslist_archive:
                        attachObj = self.get_archive_obj(fname, maxsize_extract, noextractinfo)
                        if attachObj is not None:
                            newlist.extend(attachObj.get_objectlist(levelin+1,levelmax,maxsize_extract, noextractinfo))
                else:
                    for fname in self.fileslist_archive:
                        attachObj = self.get_archive_obj(fname, maxsize_extract,noextractinfo)
                        if attachObj is not None:
                            newlist.append(attachObj)
                return newlist
            else:
                return [self]
        elif self.is_archive and noextractinfo is not None:
            for fname in self.fileslist_archive:
                noextractinfo.append((fname,"level","level (current/max) %u/%u"%(levelin,levelmax)))
        return [self]

    @smart_cached_memberfunc(inputs=['fileslist_archive','archive_handle','is_archive'])
    def get_archive_flist(self, maxsize_extract=None, inverse=False):
        """
        Get list of all filenames for objects in archive if within size limits. The list
        is consistent with the object list that would be returned by 'get_archive_objlist' or
        the inverse of it.
        Note: This will extract objects withing the limit if not already extracted!

        Here caching is allowed. Even if the attachment Object is destroyed, the filename
        remains valid (unlike the object reference returned by get_archive_objlist for uncached objects)

        Keyword Args:
            maxsize_extract (int): Maximum size that will be extracted
            inverse (bool): invert list

        Returns:

        """
        matchlist = []
        inverselist = []
        if self.is_archive:
            for fname in self.fileslist_archive:
                attachObj = self.get_archive_obj(fname, maxsize_extract)
                if attachObj is not None:
                    matchlist.append(fname)
                else:
                    inverselist.append(fname)
        return inverselist if inverse else matchlist

    def get_archive_objlist(self, maxsize_extract=None, noextractinfo=None):
        """
        Get list of all object in archive (extracts the archive) if within size limits.
        If the file is already extracted the file will be returned even if the size is
        larger than 'maxsize_extract'.

        No caching of the lists here because get_archive_obj might return an
        uncached object. The list returned here contains only references and therefore
        the caching of the list would make the uncached object permanent because the
        garbage collector can not remove it because of the reference count.

        Args:
            maxsize_extract (int): Maximum size that will be extracted

        Keyword Args:
            noextractinfo (list): list with info why object was not extracted

        Returns:
            list containing objects contained in archive

        """
        newlist = []
        if self.is_archive:
            for fname in self.fileslist_archive:
                attach_obj = self.get_archive_obj(fname, maxsize_extract, noextractinfo)
                if attach_obj is not None:
                    newlist.append(attach_obj)
        return newlist

    def get_archive_obj(self, fname, maxsize_extract, noextractinfo=None):
        """
        Get cached archive object or create a new one.

        Args:
            fname (str): filename of file object
            maxsize_extract (int): Maximum size that will be extracted

        Keyword Args:
            noextractinfo (list): list with info why object was not extracted

        Returns:
            (Mailattachment): Requested object from archive

        """
        if not self.is_archive:
            return None
        else:
            try:
                obj = self._buffer_archobj[fname]
            except KeyError:
                filesize = self.archive_handle.filesize(fname)
                buffer = self.archive_handle.extract(fname,maxsize_extract)
                if buffer is None:
                    if noextractinfo is not None:
                        if filesize > maxsize_extract:
                            noextractinfo.append((fname,"size","not extracted: %u > %u"%(filesize,maxsize_extract)))
                        else:
                            noextractinfo.append((fname,"archivehandle","(no info)"))
                    return None
                obj = Mailattachment(buffer, fname, self._mgr, filesize=filesize, in_obj=self)

                # This object caching is outside the caching decorator used in other parts of this
                # file (not for this function anyway...).
                if self._mgr.use_caching(filesize):
                    self._buffer_archobj[fname] = obj
            return obj

    @smart_cached_memberfunc(inputs=['fileslist_archive','archive_handle'])
    def get_fileslist_arch(self,levelin,levelmax,maxsize_extract):
        """
        Get a list of filenames contained in this archive (recursively extracting archives)
        or the current object filename if this is not an archive.

        Internal:
            - fileslist_archive: The list of archive filenames
            - archive_handle: The archive handle to work with the archvie

        Args:
            levelin  (in): Current recursive level
            levelmax (in): Max recursive archive level up to which archives are extracted
            maxsize_extract (int): Maximum size that will be extracted to further go into archive

        Returns:
            (list[str]): List with filenames contained in this object or this object filename itself
        """
        newlist = []
        if self.fileslist_archive is not None:
            for fname in self.fileslist_archive:
                attach_obj = self.get_archive_obj(fname, maxsize_extract)
                if attach_obj is not None:
                    newlist.extend(attach_obj.get_fileslist(levelin+1,levelmax,maxsize_extract))
        return newlist

    @smart_cached_property(inputs=['archive_type','buffer'])
    def archive_handle(self):
        """
        (Cached Property-Getter)

        Create an archive handle to check, extract, ... files in the buffered archive.

        Internal:
            - archive_type: The archive type (already detected)
            - buffer: The file buffer containing the archive

        Returns:
           (Archivehandle) : The handle to work with the archive

        """
        # make sure there's not buffered archive object when
        # the archive handle is created (or overwritten)
        self._buffer_archobj = {}
        if self.buffer is None:
            return None
        else:
            return Archivehandle(self.archive_type, BytesIO(self.buffer))

    @smart_cached_property(inputs=['archive_handle'])
    def fileslist_archive(self):
        """
        (Cached Property-Getter)

        Internal:
            - archive_type: The archive type (already detected)
            - buffer: The file buffer containing the archive

        Returns:
           (Archivehandle) : The handle to work with the archive

        """
        if self.archive_handle is None:
            return []
        else:
            return self.archive_handle.namelist()

    @smart_cached_property(inputs=["in_obj"])
    def parent_archives(self):
        """
        (Cached Property-Getter)

        The ordered list of parent objects this file was extracted from.
        First element is the direct parent (if existing).

        Returns:
           (list[Mailattachment]) : list of parents

        """
        parentsList = []
        upstream_obj = self
        while upstream_obj.in_obj is not None:
            parentsList.append(upstream_obj.in_obj)
            upstream_obj = upstream_obj.in_obj
        return parentsList


    def __str__(self):
        """
        String conversion function for object. Creates
        a string with some basic information
        Returns:
            (str): string with object information

        """
        if sys.version_info > (3,):
            element_of = u" \u2208 "
        else:
            element_of = u" IS_IN "
        return u"""
Filename     : %s        
Size (bytes) : %s    
Location     : %s        
Archive type : %s        
Content type : %s""" % (self.filename,u'(unknown)' if self.filesize is None else str(self.filesize),
                        self.filename + element_of + element_of.join([u"{" + obj.filename +u"}" for obj in self.parent_archives]),
                        self.archive_type,
                        self.contenttype)


class Mailattachment_mgr(object):
    """Mail attachment manager"""

    def __init__(self,msgrep,section=None,cachelimit=None):
        """
        Constructor, initialised by message.

        Args:
            msgrep (email.message.Message): Message to work with
        """
        self._msgrep = msgrep
        if section is None:
            self.section = self.__class__.__name__
        else:
            self.section = section

        myclass = self.__class__.__name__
        loggername = "fuglu.%s" % myclass
        self._logger = logging.getLogger(loggername)

        try:
            # Python 2
            maxinteger = sys.maxint
        except AttributeError:
            # Python 3
            maxinteger = sys.maxsize

        # to limit the size of the attachment cache
        self._current_att_cache = 0
        self._new_att_cache = 0
        self._cache_limit = cachelimit
        self._mailatt_obj_counter = 0

    def _increment_ma_objects(self):
        """
        For caching testing and debugging purposes count the number
        of Mailattachment objects created
        """
        self._mailatt_obj_counter += 1


    def use_caching(self, used_size):
        """
        Used to decide if new attachment objects inside other attachments should be cached or noe

        Returns:
            bool : True to cache the object

        """
        self._new_att_cache = self._current_att_cache + (used_size if used_size else 0)

        if  True if self._cache_limit is None else self._cache_limit >= self._new_att_cache:
            self._current_att_cache += (used_size if used_size else 0)
            return True
        else:
            return False


    def walk_all_parts(self, message):
        """
        Like email.message.Message's .walk() but also tries to find parts in the message's epilogue.

        Args:
            message (email.message.Message):

        Returns:
            (iterator): to iterate over message parts

        """
        for part in message.walk():
            yield part

        boundary = message.get_boundary()
        epilogue = message.epilogue
        if epilogue is None or boundary not in epilogue:
            return

        candidate_parts = epilogue.split(boundary)
        for candidate in candidate_parts:
            try:
                part_content = candidate.strip()
                if part_content.lower().startswith('content'):
                    message = email.message_from_string(part_content)
                    yield message

            except Exception as e:
                self.logger.info("hidden part extraction failed: %s"%str(e))


    @smart_cached_property(inputs=["_msgrep"])
    def att_file_dict(self):
        """
        (Cached Property-Getter)

        Dictionary storing attachments in mail. Key is filename, value is list of
        Mailattachment objects for given name.

        Internal member dependencies:
            - _msgrep (email.message.Message): Email message

        Returns:
            (dict): Dictionary storing attachments in list
        """
        newatt_file_dict = dict()

        # reset caching
        self._current_att_cache = 0
        self._new_att_cache = 0

        counter = 0
        for part in self.walk_all_parts(self._msgrep):
            if part.is_multipart():
                continue

            # use a linear counter
            counter += 1

            # process part, extract information needed to create Mailattachment
            (att_name, buffer, attsize,
             contenttype_mime, maintype_mime, subtype_mime,
             ismultipart_mime, content_charset_mime) = Mailattachment_mgr.process_msg_part(part)

            if self.use_caching(attsize):
                # cache the object if a cachelimit is defined
                # and if size could be extracted and is within the limit
                newatt_file_dict[counter] = Mailattachment(buffer, att_name, self, filesize=attsize,
                                                           contenttype_mime=contenttype_mime,
                                                           maintype_mime=maintype_mime, subtype_mime=subtype_mime,
                                                           ismultipart_mime=ismultipart_mime,
                                                           content_charset_mime=content_charset_mime)
            else:
                # No caching of the object
                newatt_file_dict[counter] = None
        return newatt_file_dict

    def get_mailatt_generator(self):
        """
        Dictionary storing attachments in mail. Key is filename, value is list of
        Mailattachment objects for given name.

        Internal member dependencies:
            - _msgrep (email.message.Message): Email message

        Returns:
            (dict): Dictionary storing attachments in list
        """

        counter = 0
        for part in self.walk_all_parts(self._msgrep):
            if part.is_multipart():
                continue
            counter += 1

            # use cached object if available
            cached_obj = self.att_file_dict.get(counter)
            if cached_obj is not None:
                #---------------#
                # Cached object #
                #---------------#
                yield cached_obj
            else:
                #-----------------#
                # UNCached object #
                #-----------------#

                # process part, extract information needed to create Mailattachment
                (att_name, buffer, attsize, contenttype_mime, maintype_mime, subtype_mime,
                 ismultipart_mime, content_charset_mime) = Mailattachment_mgr.process_msg_part(part)
                att = Mailattachment(buffer, att_name, self, filesize=attsize, contenttype_mime=contenttype_mime,
                                     maintype_mime=maintype_mime, subtype_mime=subtype_mime,
                                     ismultipart_mime=ismultipart_mime, content_charset_mime=content_charset_mime)
                yield att

    @staticmethod
    def process_msg_part(part):
        """
        Process message part, return tuple containing all information to create Mailattachment object

        Args:
            part (message part):

        Returns:
            tuple : tuple containing

        -   att_name             (string) : attachment filename
        -   buffer               (bytes)  : attachment buffer as bytes
        -   attsize              (int)    : attachment size in bytes
        -   contenttype_mime     (string) : content type
        -   maintype_mime        (string) : main content type
        -   subtype_mime         (string) : content subtype
        -   ismultipart_mime     (bool)   : multipart
        -   content_charset_mime (string) : charset for content

        """
        contenttype_mime     = part.get_content_type()
        maintype_mime        = part.get_content_maintype()
        subtype_mime         = part.get_content_subtype()
        ismultipart_mime     = part.is_multipart()
        content_charset_mime = part.get_content_charset()
        att_name             = part.get_filename(None)

        if att_name:
            # some filenames are encoded, try to decode
            try:
                att_name = ''.join([x[0] for x in decode_header(att_name)])
            except Exception:
                pass
        else:
            ct = part.get_content_type()
            if ct in MIMETYPE_EXT_OVERRIDES:
                ext = MIMETYPE_EXT_OVERRIDES[ct]
            else:
                exts = mimetypes.guess_all_extensions(ct)
                # reply is randomly sorted list, get consistent result
                if len(exts)>0:
                    exts.sort()
                    ext = exts[0]
                else:
                    ext = None

            if ext is None:
                ext = ''

            if ext.strip() == '':
                att_name = "unnamed"
            else:
                att_name = 'unnamed.%s' % ext

        buffer = part.get_payload(decode=True) # Py2: string, Py3: bytes
        # try to get size from buffer length
        try:
            attsize = len(buffer)
        except Exception:
            attsize = None
        return (att_name, buffer, attsize,
                contenttype_mime, maintype_mime, subtype_mime, ismultipart_mime, content_charset_mime)

    @smart_cached_memberfunc(inputs=['att_file_dict'])
    def get_fileslist(self,level=0,maxsize_extract=None):
        """
        (Cached Member Function)

        Get list of all filenames attached to message. For given recursion level attached
        archives are extracted to get filenames.

        Internal member dependencies:
            - att_file_dict (dict): The internal dictionary storing attached files as Mailattachment objects.

        Keyword Args:
            level (in): Level up to which archives are opened to get file list (default: 0 -> only filenames directly attached)
            - maxsize_extract (int): maximum file size to extract if asked for the file object

        Returns:
            list[str]: list containing attached files with archives extracted to given level
        """
        file_list = []
        for att_obj in self.get_mailatt_generator():
            file_list.extend(att_obj.get_fileslist(0, level, maxsize_extract))
        return file_list

    def get_objectlist(self,level=0, maxsize_extract=None):
        """
        Get list of all Mailattachment objects attached to message. For given recursion level attached
        archives are extracted.

        No caching allowed since objects might not be cached...

        Keyword Args:
            level (in): Level up to which archives are opened to get file list (default: 0 -> direct mail attachments)

        Returns:
            list[Mailattachment]: list containing attached files with archives extracted to given level
        """
        obj_list = []
        for att_obj in self.get_mailatt_generator():
            obj_list.extend(att_obj.get_objectlist(0,level,maxsize_extract))
        return obj_list

