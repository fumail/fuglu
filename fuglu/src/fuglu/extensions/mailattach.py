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
    def __init__(self,buffer,filename,inObj=None):
        self.filename = filename
        self.buffer = buffer
        self._buffer_archObj = {}
        self.inObj = inObj

    @smart_cached_property(inputs=['buffer'])
    def contenttype(self):
        contenttype_magic = None
        if filetype_handler.available():
            contenttype_magic = filetype_handler.get_buffertype(self.buffer)
        return contenttype_magic

    @smart_cached_property(inputs=['contenttype','filename'])
    def archive_type(self):
        # try guessing the archive type based on magic content type first
        archive_type = Archivehandle.archive_type_from_content_type(self.contenttype)

        # if it didn't work, try to guess by the filename extension, if it is enabled
        if archive_type is None:
            # sort by length, so tar.gz is checked before .gz
            for arext in Archivehandle.avail_archive_extensions_list:

                if self.filename.lower().endswith('.%s' % arext):
                    archive_type = Archivehandle.avail_archive_extensions[arext]
                    break
        return archive_type

    @smart_cached_property(inputs=['archive_type'])
    def isArchive(self):
        return self.archive_type is not None

    #@smart_cached_memberfunc(inputs=['attFileDict'])
    def get_fileslist(self,levelin, levelmax):
        if levelmax is None or levelin < levelmax:
            if self.isArchive:
                if levelmax is None or levelin + 1 < levelmax:
                    return self.get_fileslist_arch(levelin,levelmax)
                else:
                    return self.fileslist_archive

        return [self.filename]

    def get_objectlist(self,levelin, levelmax):
        if levelmax is None or levelin < levelmax:

            if self.isArchive:

                newlist = []
                if levelmax is None or levelin + 1 < levelmax:
                    #return self.get_fileslist_arch(levelin,levelmax)
                    for fname in self.fileslist_archive:
                        attachObj = self.get_archiveObj(fname)
                        newlist.extend(attachObj.get_objectlist(levelin+1,levelmax))
                else:
                    for fname in self.fileslist_archive:
                        attachObj = self.get_archiveObj(fname)
                        newlist.append(attachObj)
                return newlist

        return [self]

    def get_archiveObj(self,fname):
        if not self.isArchive:
            return None
        else:
            try:
                obj = self._buffer_archObj[fname]
            except KeyError:
                buffer = self.archive_handle.extract(fname,500000)
                obj = MailAttachment(buffer,fname,self)
                self._buffer_archObj[fname] = obj
            return obj

    @smart_cached_memberfunc(inputs=['fileslist_archive','archive_handle'])
    def get_fileslist_arch(self,levelin,levelmax):
        newlist = []
        for fname in self.fileslist_archive:
            attachObj = self.get_archiveObj(fname)
            newlist.extend(attachObj.get_fileslist(levelin+1,levelmax))
        return newlist

    @smart_cached_property(inputs=['archive_type','buffer'])
    def archive_handle(self):
        # make sure there's not buffered archive object when
        # the archive handle is created (or overwritten)
        self._buffer_archObj = {}
        return Archivehandle(self.archive_type, BytesIO(self.buffer))

    @smart_cached_property(inputs=['archive_handle'])
    def fileslist_archive(self):
        return self.archive_handle.namelist()

    @smart_cached_property(inputs=[])
    def parentArchives(self):
        parentsList = []
        upstreamObj = self
        while upstreamObj.inObj is not None:
            parentsList.append(upstreamObj.inObj)
            upstreamObj = upstreamObj.inObj
        return parentsList


    def __str__(self):
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
        self._msgrep = msgrep

    def set(self,msgrep):
        self._msgrep = msgrep

    def walk_all_parts(self, message):
        """Like email.message.Message's .walk() but also tries to find parts in the message's epilogue"""
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

    @smart_cached_property(inputs=[])
    def attFileDict(self):
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
            att = MailAttachment(buffer,att_name)
            fileList.append(att)
        return attFileDict

    @smart_cached_memberfunc(inputs=['attFileDict'])
    def get_fileslist(self,level=None):
        fileList = []
        for fname,attObjList in iter(self.attFileDict.items()):
            for attObj in attObjList:
                fileList.extend(attObj.get_fileslist(0,level))
        return fileList

    @smart_cached_memberfunc(inputs=['attFileDict'])
    def get_objectlist(self,level=None):
        objList = []
        for fname,attObjList in iter(self.attFileDict.items()):
            for attObj in attObjList:
                objList.extend(attObj.get_objectlist(0,level))
        return objList

    def get_attIDs(self,filename):
        return self.attFileDict[filename]

    #def get_filetype(self,attID):
