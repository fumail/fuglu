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
#

# http://vaibhavkulkarni.wordpress.com/2007/11/19/a-icap-client-code-in-c-to-virus-scan-a-file-using-symantec-scan-server/

from fuglu.shared import ScannerPlugin, string_to_actioncode, DEFER, DUNNO, actioncode_to_string, Suspect, apply_template
import socket
import os


class ICAPPlugin(ScannerPlugin):

    """ICAP Antivirus Plugin
This plugin allows Antivirus Scanning over the ICAP Protocol (http://tools.ietf.org/html/rfc3507 )
supported by some AV Scanners like Symantec and Sophos. For sophos, however, it is recommended to use the native SSSP Protocol.

Prerequisites: requires an ICAP capable antivirus engine somewhere in your network
"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {
            'host': {
                'default': 'localhost',
                'description': 'hostname where the ICAP server runs',
            },

            'port': {
                'default': '1344',
                'description': "tcp port or path to unix socket",
            },

            'timeout': {
                'default': '10',
                'description': 'socket timeout',
            },

            'maxsize': {
                'default': '22000000',
                'description': "maximum message size, larger messages will not be scanned. ",
            },

            'retries': {
                'default': '3',
                'description': 'how often should fuglu retry the connection before giving up',
            },

            'virusaction': {
                'default': 'DEFAULTVIRUSACTION',
                'description': "action if infection is detected (DUNNO, REJECT, DELETE)",
            },

            'problemaction': {
                'default': 'DEFER',
                'description': "action if there is a problem (DUNNO, DEFER)",
            },

            'rejectmessage': {
                'default': 'threat detected: ${virusname}',
                'description': "reject message template if running in pre-queue mode and virusaction=REJECT",
            },

            'service': {
                'default': 'AVSCAN',
                'description': 'ICAP Av scan service, usually AVSCAN (sophos, symantec)',
            },

            'enginename': {
                'default': 'icap-generic',
                'description': "name of the virus engine behind the icap service. used to inform other plugins. can be anything like 'sophos', 'symantec', ...",
            },
        }
        self.logger = self._logger()

    def __str__(self):
        return "ICAP AV"

    def _problemcode(self):
        retcode = string_to_actioncode(
            self.config.get(self.section, 'problemaction'), self.config)
        if retcode != None:
            return retcode
        else:
            # in case of invalid problem action
            return DEFER

    def examine(self, suspect):

        enginename = self.config.get(self.section, 'enginename')

        if suspect.size > self.config.getint(self.section, 'maxsize'):
            self.logger.info('Not scanning - message too big')
            return

        content = suspect.get_source()

        for i in range(0, self.config.getint(self.section, 'retries')):
            try:
                viruses = self.scan_stream(content)
                if viruses != None:
                    self.logger.info(
                        "Virus found in message from %s : %s" % (suspect.from_address, viruses))
                    suspect.tags['virus'][enginename] = True
                    suspect.tags['%s.virus' % enginename] = viruses
                    suspect.debug('viruses found in message : %s' % viruses)
                else:
                    suspect.tags['virus'][enginename] = False

                if viruses != None:
                    virusaction = self.config.get(self.section, 'virusaction')
                    actioncode = string_to_actioncode(virusaction, self.config)
                    firstinfected, firstvirusname = list(viruses.items())[0]
                    values = dict(
                        infectedfile=firstinfected, virusname=firstvirusname)
                    message = apply_template(
                        self.config.get(self.section, 'rejectmessage'), suspect, values)
                    return actioncode, message
                return DUNNO
            except Exception as e:
                self.logger.warning("Error encountered while contacting ICAP server (try %s of %s): %s" % (
                    i + 1, self.config.getint(self.section, 'retries'), str(e)))
        self.logger.error("ICAP scan failed after %s retries" %
                          self.config.getint(self.section, 'retries'))
        content = None
        return self._problemcode()

    def scan_stream(self, buf):
        """
        Scan a buffer

        buffer (string) : buffer to scan

        return either :
          - (dict) : {filename1: "virusname"}
          - None if no virus found
        """

        s = self.__init_socket__()
        dr = {}

        CRLF = "\r\n"
        host = self.config.get(self.section, 'host')
        port = self.config.get(self.section, 'port')
        service = self.config.get(self.section, 'service')
        buflen = len(buf)

        # in theory, these fake headers are optional according to the ICAP errata
        # and sophos docs
        # but better be safe than sorry

        fakerequestheader = "GET http://localhost/message.eml HTTP/1.1" + CRLF
        fakerequestheader += "Host: localhost" + CRLF
        fakerequestheader += CRLF
        fakereqlen = len(fakerequestheader)

        fakeresponseheader = "HTTP/1.1 200 OK" + CRLF
        fakeresponseheader += "Content-Type: message/rfc822" + CRLF
        fakeresponseheader += "Content-Length: " + str(buflen) + CRLF
        fakeresponseheader += CRLF
        fakeresplen = len(fakeresponseheader)

        bodyparthexlen = hex(buflen)[2:]
        bodypart = bodyparthexlen + CRLF
        bodypart += buf + CRLF
        bodypart += "0" + CRLF

        hdrstart = 0
        responsestart = fakereqlen
        bodystart = fakereqlen + fakeresplen

        # now that we know the length of the fake request/response, we can
        # build the ICAP header
        icapheader = ""
        icapheader += "RESPMOD icap://%s:%s/%s ICAP/1.0 %s" % (
            host, port, service, CRLF)
        icapheader += "Host: " + host + CRLF
        icapheader += "Allow: 204" + CRLF
        icapheader += "Encapsulated: req-hdr=%s, res-hdr=%s, res-body=%s%s" % (
            hdrstart, responsestart, bodystart, CRLF)
        icapheader += CRLF

        everything = icapheader + fakerequestheader + \
            fakeresponseheader + bodypart + CRLF
        s.sendall(everything)
        result = s.recv(20000)
        s.close()

        sheader = "X-Violations-Found:"
        if sheader.lower() in result.lower():
            lines = result.split('\n')
            lineidx = 0
            for line in lines:
                if sheader.lower() in line.lower():
                    numfound = int(line[len(sheader):])
                    # for each found virus, get 4 lines
                    for vircount in range(numfound):
                        infectedfile = lines[
                            lineidx + vircount * 4 + 1].strip()
                        infection = lines[lineidx + vircount * 4 + 2].strip()
                        dr[infectedfile] = infection

                    break
                lineidx += 1

        if dr == {}:
            return None
        else:
            return dr

    def __init_socket__(self):
        icap_HOST = self.config.get(self.section, 'host')
        unixsocket = False

        try:
            iport = int(self.config.get(self.section, 'port'))
        except ValueError:
            unixsocket = True

        if unixsocket:
            sock = self.config.get(self.section, 'port')
            if not os.path.exists(sock):
                raise Exception("unix socket %s not found" % sock)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.config.getint(self.section, 'timeout'))
            try:
                s.connect(sock)
            except socket.error:
                raise Exception(
                    'Could not reach ICAP server using unix socket %s' % sock)
        else:
            icap_PORT = int(self.config.get(self.section, 'port'))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.config.getint(self.section, 'timeout'))
            try:
                s.connect((icap_HOST, icap_PORT))
            except socket.error:
                raise Exception(
                    'Could not reach ICAP server using network (%s, %s)' % (icap_HOST, icap_PORT))

        return s

    def lint(self):
        viract = self.config.get(self.section, 'virusaction')
        print("Virusaction: %s" % actioncode_to_string(
            string_to_actioncode(viract, self.config)))
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
        print("ICAP server found virus", result)
        return True
