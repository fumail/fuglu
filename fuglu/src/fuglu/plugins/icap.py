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
#

# http://vaibhavkulkarni.wordpress.com/2007/11/19/a-icap-client-code-in-c-to-virus-scan-a-file-using-symantec-scan-server/

from fuglu.shared import AVScannerPlugin, string_to_actioncode, DEFER, DUNNO, actioncode_to_string, apply_template
import socket
import os


class ICAPPlugin(AVScannerPlugin):

    """ICAP Antivirus Plugin
This plugin allows Antivirus Scanning over the ICAP Protocol (http://tools.ietf.org/html/rfc3507 )
supported by some AV Scanners like Symantec and Sophos. For sophos, however, it is recommended to use the native SSSP Protocol.

Prerequisites: requires an ICAP capable antivirus engine somewhere in your network
"""

    def __init__(self, config, section=None):
        AVScannerPlugin.__init__(self, config, section)
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
        self.enginename = 'icap-generic'
    
    
    def __str__(self):
        return "ICAP AV"
    
    
    def examine(self, suspect):
        if self._check_too_big(suspect):
            return DUNNO
        self.enginename = self.config.get(self.section, 'enginename')

        content = suspect.get_source()

        for i in range(0, self.config.getint(self.section, 'retries')):
            try:
                viruses = self.scan_stream(content, suspect.id)
                actioncode, message = self._virusreport(suspect, viruses)
                return actioncode, message
            except Exception as e:
                self.logger.warning("Error encountered while contacting ICAP server (try %s of %s): %s" % (
                    i + 1, self.config.getint(self.section, 'retries'), str(e)))
        self.logger.error("ICAP scan failed after %s retries" %
                          self.config.getint(self.section, 'retries'))
        
        return self._problemcode()
    
    
    def scan_stream(self, content, suspectid='(NA)'):
        """
        Scan a buffer

        content (string) : buffer to scan

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
        buflen = len(content)

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
        bodypart += content + CRLF
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
        unixsocket = False

        try:
            int(self.config.get(self.section, 'port'))
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
            host = self.config.get(self.section, 'host')
            port = int(self.config.get(self.section, 'port'))
            timeout = int(self.config.get(self.section, 'timeout'))
            try:
                s = socket.create_connection((host, port), timeout)
            except socket.error:
                raise Exception(
                    'Could not reach ICAP server using network (%s, %s)' % (host, port))

        return s
    
    
    def lint(self):
        viract = self.config.get(self.section, 'virusaction')
        print("Virusaction: %s" % actioncode_to_string(
            string_to_actioncode(viract, self.config)))
        allok = self.check_config() and self.lint_eicar()
        return allok

