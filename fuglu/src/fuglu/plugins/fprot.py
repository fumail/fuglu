# -*- coding: UTF-8 -*-
#   Copyright 2009-2018 Oli Schacher
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
from fuglu.shared import AVScannerPlugin, DUNNO, DEFER, string_to_actioncode, apply_template
from fuglu.localStringEncoding import force_bString, force_uString
import socket
import re
import os


class FprotPlugin(AVScannerPlugin):

    """ This plugin passes suspects to a f-prot scan daemon

Prerequisites: f-protd must be installed and running, not necessarily on the same box as fuglu though.

Notes for developers:


Tags:

 * sets ``virus['F-Prot']`` (boolean)
 * sets ``FprotPlugin.virus`` (list of strings) - virus names found in message
"""

    def __init__(self, config, section=None):
        AVScannerPlugin.__init__(self, config, section)
        self.logger = self._logger()

        self.requiredvars = {
            'host': {
                'default': 'localhost',
                'description': 'hostname where fpscand runs',
            },
            'port': {
                'default': '10200',
                'description': "fpscand port",
            },
            'timeout': {
                'default': '30',
                'description': "network timeout",
            },
            'networkmode': {
                'default': '0',
                'description': "if fpscand runs on a different host than fuglu, set this to 1 to send the message over the network instead of just the filename",
            },
            'scanoptions': {
                'default': '',
                'description': 'additional scan options  (see `man fpscand` -> SCANNING OPTIONS for possible values)',
            },
            'maxsize': {
                'default': '10485000',
                'description': "maximum message size to scan",
            },
            'retries': {
                'default': '3',
                'description': "maximum retries on failed connections",
            },
            'virusaction': {
                'default': 'DEFAULTVIRUSACTION',
                'description': "plugin action if threat is detected",
            },
            'problemaction': {
                'default': 'DEFER',
                'description': "plugin action if scan fails",
            },

            'rejectmessage': {
                'default': 'threat detected: ${virusname}',
                'description': "reject message template if running in pre-queue mode and virusaction=REJECT",
            },
        }

        self.pattern = re.compile(b'^(\d)+ <(.+)> (.+)$')
        self.enginename = 'F-Prot'
    
    
    def examine(self, suspect):
        if self._check_too_big(suspect):
            return DUNNO

        try:
           content = suspect.get_message_rep().as_bytes()
        except AttributeError:
           content = force_bString(suspect.get_message_rep().as_string())

        for i in range(0, self.config.getint(self.section, 'retries')):
            try:
                if self.config.getboolean(self.section, 'networkmode'):
                    viruses = self.scan_stream(content, suspect.id)
                else:
                    viruses = self.scan_file(suspect.tempfile)
                actioncode, message = self._virusreport(suspect, viruses)
                return actioncode, message
            except Exception as e:
                self.logger.warning("%s Error encountered while contacting fpscand (try %s of %s): %s" %
                                       (suspect.id, i + 1, self.config.getint(self.section, 'retries'), str(e)))
        self.logger.error("fpscand failed after %s retries" %
                             self.config.getint(self.section, 'retries'))
        
        return self._problemcode()
    
    
    def _parse_result(self, result):
        dr = {}
        result = force_uString(result)
        for line in result.strip().split('\n'):
            m = self.pattern.match(force_bString(line))
            if m is None:
                self.logger.error(
                    'Could not parse line from f-prot: %s' % line)
                raise Exception('f-prot: Unparseable answer: %s' % result)
            status = force_uString(m.group(1))
            text = force_uString(m.group(2))
            details = force_uString(m.group(3))

            status = int(status)
            self.logger.debug("f-prot scan status: %s" % status)
            self.logger.debug("f-prot scan text: %s" % text)
            if status == 0:
                continue

            if status > 3:
                self.logger.warning(
                    "f-prot: got unusual status %s" % status)

            # http://www.f-prot.com/support/helpfiles/unix/appendix_c.html
            if status & 1 == 1 or status & 2 == 2:
                # we have a infection
                if text[0:10] == "infected: ":
                    text = text[10:]
                elif text[0:27] == "contains infected objects: ":
                    text = text[27:]
                else:
                    self.logger.warn(
                        "Unexpected reply from f-prot: %s" % text)
                    continue
                dr[details] = text

        if len(dr) == 0:
            return None
        else:
            return dr
    
    
    def scan_file(self, filename):
        filename = os.path.abspath(filename)
        s = self.__init_socket__()
        s.sendall(force_bString('SCAN %s FILE %s' %
                  (self.config.get(self.section, 'scanoptions'), filename)))
        s.sendall(b'\n')

        result = s.recv(20000)
        if len(result) < 1:
            self.logger.error('Got no reply from fpscand')
        s.close()

        return self._parse_result(result)
    
    
    def scan_stream(self, content, suspectid='(NA)'):
        """
        Scan a buffer

        content (string) : buffer to scan

        return either :
          - (dict) : {filename1: "virusname"}
          - None if no virus found
        """

        s = self.__init_socket__()
        content = force_bString(content)
        buflen = len(content)
        s.sendall(force_bString('SCAN %s STREAM fu_stream SIZE %s' %
                  (self.config.get(self.section, 'scanoptions'), buflen)))
        s.sendall(b'\n')
        self.logger.debug(
            '%s Sending buffer (length=%s) to fpscand...' % (suspectid, buflen))
        s.sendall(content)
        self.logger.debug(
            '%s Sent %s bytes to fpscand, waiting for scan result' % (suspectid, buflen))

        result = force_uString(s.recv(20000))
        if len(result) < 1:
            self.logger.error('Got no reply from fpscand')
        s.close()

        return self._parse_result(result)
    
    
    def __init_socket__(self):
        host = self.config.get(self.section, 'host')
        port = self.config.getint(self.section, 'port')
        socktimeout = self.config.getint(self.section, 'timeout')
        try:
            s = socket.create_connection((host, port), socktimeout)
        except socket.error:
            raise Exception('Could not reach fpscand using network (%s, %s)' % (
                self.config.get(self.section, 'host'), self.config.getint(self.section, 'port')))

        return s
    
    
    def __str__(self):
        return 'F-Prot AV'
    
    
    def lint(self):
        allok = self.check_config() and self.lint_eicar()
        return allok

