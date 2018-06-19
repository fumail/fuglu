import mimetypes
import threading
from email.header import decode_header
import email
from fuglu.extensions.filearchives import Archivehandle
from fuglu.extensions.filetype import filetype_handler
from fuglu.extensions.caching import smart_cached_property
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
    def __init__(self,buffer,filename):
        self.filename = filename
        self.buffer = buffer

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

    def isArchive(self):
        return self.archive_type is not None

    def files_list(self):
        if self.isArchive:
            archive_handle = Archivehandle(self.archive_type, BytesIO(self.buffer))
            namelist = archive_handle.namelist()
            return [namelist]
        else:
            return [self.filename]


class MailAttachMgr(object):
    """Mail attachment manager"""
    def __init__(self,msgrep):
        self._msgrep = msgrep
        self._attFileDict = dict()

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
    def filenames1stLevel(self):
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

            fileList = self._attFileDict.get(att_name)
            if fileList is None:
                fileList = list()
                self._attFileDict[att_name] = fileList

            buffer = part.get_payload(decode=True) # Py2: string, Py3: bytes
            att = MailAttachment(buffer,att_name)
            fileList.append(att)
            print("Attachment filename: %s, isArchive: %s"%(att.filename,att.isArchive()))
        return [filename for filename in iter(self._attFileDict.keys())]

    def get_attIDs(self,filename):
        return self.attFileDict[filename]

    #def get_filetype(self,attID):
