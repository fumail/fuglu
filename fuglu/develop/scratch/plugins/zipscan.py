from fuglu.shared import ScannerPlugin, string_to_actioncode, DEFER, DUNNO, actioncode_to_string,\
    DELETE, Suspect, apply_template

import zipfile
import time
import re
import os
import os.path
import logging
import unittest
import mimetypes
from fuglu.extensions.sql import DBFile
try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO


from threading import Lock


class ZIPScannerPlugin(ScannerPlugin):

    """Block file extension ins zip attachments"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = self._logger()

        self.requiredvars = {
            'maxsize': {
                'default': '33145728',
                'description': "max message size to check for zip attachments",
            },
            'blockaction': {
                'default': 'DUNNO',
                'description': 'what should the plugin do when a blocked attachment is detected\nREJECT : reject the message (recommended in pre-queue mode)\nDELETE : discard messages\nDUNNO  : mark as blocked but continue anyway (eg. if you have a later quarantine plugin)',
            },
            'virusname': {
                'default': 'Gen.Zip.Threat',
                'description': 'Virusname to report',
            },
            'blockedextensions': {
                'default': 'scr,pif,com',
                'description': 'file extensions to block, separated by comma',
            },
            'rejectmessage': {
                'default': 'possible threat detected in attachment ${attachment} : ${threat}',
                'description': "reject message template if running in pre-queue mode and blockaction=REJECT",
            },

        }

    def examine(self, suspect):
        starttime = time.time()

        maxsize = self.config.getint(self.section, 'maxsize')
        if suspect.size > maxsize:
            self.logger.info('Not scanning - message too big')
            return

        blockaction = self.config.get(self.section, 'blockaction')
        blockactioncode = string_to_actioncode(blockaction)

        virusname = self.config.get(self.section, 'virusname')

        blockedcontent = self.walk(suspect)

        if blockedcontent != None:
            zipname, threat = blockedcontent.items()[0]
            self.logger.info("Threat found in zip attachment %s from %s : %s" % (
                zipname, suspect.from_address, threat))
            suspect.tags['virus']['ZIPScanner'] = True
            suspect.tags['ZIPScanner.threat'] = blockedcontent

            values = dict(attachment=zipname, threat=threat)
            message = apply_template(
                self.config.get(self.section, 'rejectmessage'), suspect, values)

            return blockactioncode, message

        else:
            suspect.tags['virus']['ZIPScanner'] = False

        endtime = time.time()
        difftime = endtime - starttime
        suspect.tags['FiletypePlugin.time'] = "%.4f" % difftime
        return DUNNO

    def walk(self, suspect):
        """walks through a message and checks each attachment according to the rulefile specified in the config"""

        blockedextensions = self.config.get(
            self.section, 'blockedextensions').split(',')

        m = suspect.getMessageRep()
        for i in m.walk():
            if i.is_multipart():
                continue
            contenttype_mime = i.get_content_type()
            att_name = i.get_filename(None)

            if not att_name:
                # workaround for mimetypes, it always takes .ksh for text/plain
                if i.get_content_type() == 'text/plain':
                    ext = '.txt'
                else:
                    ext = mimetypes.guess_extension(i.get_content_type())

                if ext == None:
                    ext = ''
                att_name = 'unnamed%s' % ext

            # we are only interested in zip files
            if not att_name.lower().endswith(".zip"):
                continue

            pl = StringIO(i.get_payload(decode=True))
            zip = zipfile.ZipFile(pl)
            namelist = zip.namelist()
            for name in namelist:
                for blocked in blockedextensions:
                    ext = ".%s" % blocked.lower().strip()
                    if name.lower().strip().endswith(ext):
                        return {self.asciionly(att_name): self.asciionly(name)}

        return None

    def asciionly(self, stri):
        """return stri with all non-ascii chars removed"""
        return "".join([x for x in stri if ord(x) < 128])

    def _debuginfo(self, suspect, message):
        """Debug to log and suspect"""
        suspect.debug(message)
        self.logger.debug(message)

    def __str__(self):
        return "ZIP Scanner"
