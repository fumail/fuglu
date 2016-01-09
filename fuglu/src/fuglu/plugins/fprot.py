#   Copyright 2009-2016 Oli Schacher
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
from fuglu.shared import ScannerPlugin, DELETE, DUNNO, DEFER, string_to_actioncode, apply_template
import socket
import time
import re
import os


class FprotPlugin(ScannerPlugin):

    """ This plugin passes suspects to a f-prot scan daemon 

Prerequisites: f-protd must be installed and running, not necessarily on the same box as fuglu though.

Notes for developers:


Tags:

 * sets ``virus['F-Prot']`` (boolean)
 * sets ``FprotPlugin.virus`` (list of strings) - virus names found in message
"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)

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

        self.pattern = re.compile('^(\d)+ <(.+)> (.+)$')

    def _problemcode(self):
        retcode = string_to_actioncode(
            self.config.get(self.section, 'problemaction'), self.config)
        if retcode != None:
            return retcode
        else:
            # in case of invalid problem action
            return DEFER

    def examine(self, suspect):
        starttime = time.time()

        if suspect.size > self.config.getint(self.section, 'maxsize'):
            self._logger().info('Not scanning - message too big (message %s  bytes > config %s bytes )' %
                                (suspect.size, self.config.getint(self.section, 'maxsize')))
            return DUNNO

        content = suspect.get_message_rep().as_string()

        for i in range(0, self.config.getint(self.section, 'retries')):
            try:
                if self.config.getboolean(self.section, 'networkmode'):
                    viruses = self.scan_stream(content)
                else:
                    viruses = self.scan_file(suspect.tempfile)
                if viruses != None:
                    self._logger().info("Virus found in message from %s : %s" %
                                        (suspect.from_address, viruses))
                    suspect.tags['virus']['F-Prot'] = True
                    suspect.tags['FprotPlugin.virus'] = viruses
                    suspect.debug('Viruses found in message : %s' % viruses)
                else:
                    suspect.tags['virus']['F-Prot'] = False

                if viruses != None:
                    virusaction = self.config.get(self.section, 'virusaction')
                    actioncode = string_to_actioncode(virusaction, self.config)
                    firstinfected, firstvirusname = list(viruses.items())[0]
                    values = dict(
                        infectedfile=firstinfected, virusname=firstvirusname)
                    message = apply_template(
                        self.config.get(self.section, 'rejectmessage'), suspect, values)
                    return actioncode, message
                else:
                    return DUNNO
            except Exception as e:
                self._logger().warning("Error encountered while contacting fpscand (try %s of %s): %s" %
                                       (i + 1, self.config.getint(self.section, 'retries'), str(e)))
        self._logger().error("fpscand failed after %s retries" %
                             self.config.getint(self.section, 'retries'))
        content = None
        return self._problemcode()

    def _parse_result(self, result):
        dr = {}
        for line in result.strip().split('\n'):
            m = self.pattern.match(line)
            if m == None:
                self._logger().error(
                    'Could not parse line from f-prot: %s' % line)
                raise Exception('f-prot: Unparseable answer: %s' % result)
            status = m.group(1)
            text = m.group(2)
            details = m.group(3)

            status = int(status)
            self._logger().debug("f-prot scan status: %s" % status)
            self._logger().debug("f-prot scan text: %s" % text)
            if status == 0:
                continue

            if status > 3:
                self._logger().warning(
                    "f-prot: got unusual status %s" % status)

            # http://www.f-prot.com/support/helpfiles/unix/appendix_c.html
            if status & 1 == 1 or status & 2 == 2:
                # we have a infection
                if text[0:10] == "infected: ":
                    text = text[10:]
                elif text[0:27] == "contains infected objects: ":
                    text = text[27:]
                else:
                    self._logger().warn(
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
        s.sendall('SCAN %s FILE %s' %
                  (self.config.get(self.section, 'scanoptions'), filename))
        s.sendall('\n')

        result = s.recv(20000)
        if len(result) < 1:
            self._logger().error('Got no reply from fpscand')
        s.close()

        return self._parse_result(result)

    def scan_stream(self, buffer):
        """
        Scan a buffer

        buffer (string) : buffer to scan

        return either :
          - (dict) : {filename1: "virusname"}
          - None if no virus found
        """

        s = self.__init_socket__()
        buflen = len(buffer)
        s.sendall('SCAN %s STREAM fu_stream SIZE %s' %
                  (self.config.get(self.section, 'scanoptions'), buflen))
        s.sendall('\n')
        self._logger().debug(
            'Sending buffer (length=%s) to fpscand...' % buflen)
        s.sendall(buffer)
        self._logger().debug(
            'Sent %s bytes to fpscand, waiting for scan result' % buflen)

        result = s.recv(20000)
        if len(result) < 1:
            self._logger().error('Got no reply from fpscand')
        s.close()

        return self._parse_result(result)

    def __init_socket__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.config.getint(self.section, 'timeout'))
        try:
            s.connect((self.config.get(self.section, 'host'),
                       self.config.getint(self.section, 'port')))
        except socket.error:
            raise Exception('Could not reach fpscand using network (%s, %s)' % (
                self.config.get(self.section, 'host'), self.config.getint(self.section, 'port')))

        return s

    def __str__(self):
        return 'F-Prot AV'

    def lint(self):
        allok = (self.checkConfig() and self.lint_eicar())
        return allok

    def lint_eicar(self):
        stream = """Date: Mon, 08 Sep 2008 17:33:54 +0200
To: oli@unittests.fuglu.org
From: oli@unittests.fuglu.org
Subject: test eicar attachment
X-Mailer: swaks v20061116.0 jetmore.org/john/code/#swaks
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_12140"

------=_MIME_BOUNDARY_000_12140
Content-Type: text/plain

Eicar test
------=_MIME_BOUNDARY_000_12140
Content-Type: application/octet-stream
Content-Transfer-Encoding: BASE64
Content-Disposition: attachment

UEsDBAoAAAAAAGQ7WyUjS4psRgAAAEYAAAAJAAAAZWljYXIuY29tWDVPIVAlQEFQWzRcUFpYNTQo
UF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoNClBLAQIU
AAoAAAAAAGQ7WyUjS4psRgAAAEYAAAAJAAAAAAAAAAEAIAD/gQAAAABlaWNhci5jb21QSwUGAAAA
AAEAAQA3AAAAbQAAAAAA

------=_MIME_BOUNDARY_000_12140--"""

        result = self.scan_stream(stream)
        if result == None:
            print("EICAR Test virus not found!")
            return False
        print("F-Prot found virus", result)
        return True
