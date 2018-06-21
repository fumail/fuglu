import mimetypes
import threading
from email.header import decode_header
import email
import sys
from fuglu.extensions.filearchives import Archivehandle
from fuglu.extensions.filetype import filetype_handler
from fuglu.extensions.caching import smart_cached_property, smart_cached_memberfunc
from io import BytesIO

# workarounds for mimetypes
# - always takes .ksh for text/plain
# - python3 takes .exe for application/octet-stream which is often used for content types
#   unknwon to the creating MUA (e.g. pdf files are often octet-stream)
MIMETYPE_EXT_OVERRIDES = {
    'text/plain': 'txt',
    'application/octet-stream': None,
}


class MailAttachment(threading.local):
    """
    Mail attachment object or a file contained in the attachment.
    """
    def __init__(self,buffer,filename,filesize=None,inObj=None,contenttype_mime=None):
        """
        Constructor
        Args:
            buffer (bytes): buffer containing attachment source
            filename (str): filename of current attachment object
            filesize (size): file size in bytes
            inObj (MailAttachment): "Father" MailAttachment object (if existing), the archive containing the current object
            contenttype_mime (str): The contenttype as defined in the mail attachment, only available for direct mail attachments
        """
        self.filename = filename
        self.filesize = filesize
        self.buffer = buffer
        self._buffer_archObj = {}
        self.inObj = inObj
        self.contenttype_mime = contenttype_mime

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
        if filetype_handler.available():
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
    def isArchive(self):
        """
        (Cached Property-Getter)

        Define if this object is an extractable archive or an ordinary file.

        Internal:
            - archive_type: Depends on the member variable 'archive_type'

        Returns:
            (bool): True for an archive that can be extracted
        """
        return self.archive_type is not None

    def get_fileslist(self,levelin, levelmax):
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

        Returns:
            (list[str]): List with filenames contained in this object of this object filename itself

        """
        if levelmax is None or levelin < levelmax:
            if self.isArchive:
                if levelmax is None or levelin + 1 < levelmax:
                    return self.get_fileslist_arch(levelin,levelmax)
                else:
                    return self.fileslist_archive

        return [self.filename]

    def get_objectlist(self,levelin, levelmax):
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

        Returns:
            (list[MailAttachment]): List with MailAttachment objects contained in this object of this object itself
        """
        if levelmax is None or levelin < levelmax:

            if self.isArchive:

                newlist = []
                if levelmax is None or levelin + 1 < levelmax:
                    for fname in self.fileslist_archive:
                        attachObj = self.get_archiveObj(fname)
                        newlist.extend(attachObj.get_objectlist(levelin+1,levelmax))
                else:
                    for fname in self.fileslist_archive:
                        attachObj = self.get_archiveObj(fname)
                        newlist.append(attachObj)
                return newlist

        return [self]

    @smart_cached_memberfunc(inputs=['fileslist_archive','archive_handle','isArchive'])
    def get_archiveFList(self,maxsize_extract=None,maxsize_get=None,inverse=False):
        """
        Get list of all filenames for objects in archive if within size limits. The list
        is consistent with the object list that would be returned by 'get_archiveObjList' or
        the inverse of it.
        Note: This will extract objects withing the limit if not already extracted!

        Keyword Args:
            maxsize_extract (int): Maximum size that will be extracted
            maxsize_get (int): Maximum size to return file
            inverse (bool): invert list

        Returns:

        """
        matchlist = []
        inverselist = []
        if self.isArchive:
            for fname in self.fileslist_archive:
                attachObj = self.get_archiveObj(fname,maxsize_extract)
                if attachObj is not None:
                    try:
                        obj = self._buffer_archObj[fname]
                        if obj.filesize is None or maxsize_get is None:
                            matchlist.append(fname)
                        elif obj.filesize <= maxsize_get:
                            matchlist.append(fname)
                        else:
                            inverselist.append(fname)
                    except KeyError:
                        inverselist.append(fname)
        return inverselist if inverse else matchlist

    @smart_cached_memberfunc(inputs=['fileslist_archive','archive_handle','isArchive'])
    def get_archiveObjList(self,maxsize_extract=None,maxsize_get=None):
        """
        Get list of all object in archive (extracts the archive) if within size limits.
        If the file is already extracted the file will be returned even if the size is
        larger than 'maxsize_extract' (as long as it is within 'maxsize_get').

        Args:
            maxsize_extract (int): Maximum size that will be extracted
            maxsize_get (int): Maximum size to return file

        Returns:

        """
        newlist = []
        if self.isArchive:
            for fname in self.fileslist_archive:
                attachObj = self.get_archiveObj(fname,maxsize_extract)
                if attachObj is not None:
                    if maxsize_get is None or attachObj.filesize is None:
                        newlist.append(attachObj)
                    elif attachObj.filesize <= maxsize_get:
                        newlist.append(attachObj)
        return newlist

    def get_archiveObj(self,fname,maxsize_extract):
        """
        Get cached archive object or create a new one.

        Args:
            fname (str): filename of file object
            maxsize_extract (int): Maximum size that will be extracted

        Returns:
            (MailAttachment): Requested object from archive

        """
        if not self.isArchive:
            return None
        else:
            try:
                obj = self._buffer_archObj[fname]
            except KeyError:
                filesize = self.archive_handle.filesize(fname)
                buffer = self.archive_handle.extract(fname,maxsize_extract)
                obj = MailAttachment(buffer,fname,inObj=self,filesize=filesize)
                self._buffer_archObj[fname] = obj
            return obj

    @smart_cached_memberfunc(inputs=['fileslist_archive','archive_handle'])
    def get_fileslist_arch(self,levelin,levelmax):
        """
        Get a list of filenames contained in this archive (recursively extracting archives)
        or the current object filename if this is not an archive.

        Internal:
            - fileslist_archive: The list of archive filenames
            - archive_handle: The archive handle to work with the archvie

        Args:
            levelin  (in): Current recursive level
            levelmax (in): Max recursive archive level up to which archives are extracted

        Returns:
            (list[str]): List with filenames contained in this object or this object filename itself
        """
        newlist = []
        for fname in self.fileslist_archive:
            attachObj = self.get_archiveObj(fname)
            newlist.extend(attachObj.get_fileslist(levelin+1,levelmax))
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
        self._buffer_archObj = {}
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
        return self.archive_handle.namelist()

    @smart_cached_property(inputs=[])
    def parentArchives(self):
        """
        (Cached Property-Getter)

        The ordered list of parent objects this file was extracted from.
        First element is the direct parent (if existing).

        Returns:
           (list[MailAttachment]) : list of parents

        """
        parentsList = []
        upstreamObj = self
        while upstreamObj.inObj is not None:
            parentsList.append(upstreamObj.inObj)
            upstreamObj = upstreamObj.inObj
        return parentsList


    def __str__(self):
        """
        String conversion function for object. Creates
        a string with some basic information
        Returns:
            (str): string with object information

        """
        if sys.version_info > (3,):
            elementOf = u" \u2208 "
        else:
            elementOf = u" IS_IN "
        return u"""
Filename : %s        
Location : %s        
Archive type : %s        
Content type : %s""" % (self.filename,
                        self.filename + elementOf + elementOf.join([u"{"+obj.filename+u"}" for obj in self.parentArchives]),
                        self.archive_type,
                        self.contenttype)


class MailAttachMgr(object):
    """Mail attachment manager"""

    def __init__(self,msgrep):
        """
        Constructor, initialised by message.

        Args:
            msgrep (email.message.Message): Message to work with
        """
        self._msgrep = msgrep


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
    def attFileDict(self):
        """
        (Cached Property-Getter)

        Dictionary storing attachments in mail. Key is filename, value is list of
        MailAttachment objects for given name.

        Internal member dependencies:
            - _msgrep (email.message.Message): Email message

        Returns:
            (dict): Dictionary storing attachments in list
        """
        attFileDict = dict()

        for part in self.walk_all_parts(self._msgrep):
            if part.is_multipart():
                continue
            contenttype_mime = part.get_content_type()
            att_name = part.get_filename(None)

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

            #print(att_name)
            #att_name = self.asciionly(att_name)

            # dict: filename: list

            fileList = attFileDict.get(att_name)
            if fileList is None:
                fileList = list()
                attFileDict[att_name] = fileList

            buffer = part.get_payload(decode=True) # Py2: string, Py3: bytes
            att = MailAttachment(buffer,att_name,contenttype_mime=contenttype_mime)
            fileList.append(att)
        return attFileDict

    @smart_cached_memberfunc(inputs=['attFileDict'])
    def get_fileslist(self,level=0):
        """
        (Cached Member Function)

        Get list of all filenames attached to message. For given recursion level attached
        archives are extracted to get filenames.

        Internal member dependencies:
            - attFileDict (dict): The internal dictionary storing attached files as MailAttachment objects.

        Keyword Args:
            level (in): Level up to which archives are opened to get file list (default: 0 -> only filenames directly attached)

        Returns:
            list[str]: list containing attached files with archives extracted to given level
        """
        fileList = []
        for fname,attObjList in iter(self.attFileDict.items()):
            for attObj in attObjList:
                fileList.extend(attObj.get_fileslist(0,level))
        return fileList

    @smart_cached_memberfunc(inputs=['attFileDict'])
    def get_objectlist(self,level=0):
        """
        (Cached Member Function)

        Get list of all MailAttachment objects attached to message. For given recursion level attached
        archives are extracted.

        Internal member dependencies:
            - attFileDict (dict): The internal dictionary storing attached files as MailAttachment objects.

        Keyword Args:
            level (in): Level up to which archives are opened to get file list (default: 0 -> direct mail attachments)

        Returns:
            list[MailAttachment]: list containing attached files with archives extracted to given level
        """
        objList = []
        for fname,attObjList in iter(self.attFileDict.items()):
            for attObj in attObjList:
                objList.extend(attObj.get_objectlist(0,level))
        return objList

