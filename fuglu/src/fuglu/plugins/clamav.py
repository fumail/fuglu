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
from fuglu.shared import ScannerPlugin, string_to_actioncode, DEFER, DUNNO, actioncode_to_string,\
    DELETE, Suspect, apply_template
import socket
import string
import os
import struct
import threading
import errno

threadLocal = threading.local()
# it's probably a good idea to re-establish the connection every now and then
MAX_SCANS_PER_SOCKET = 5000


class ClamavPlugin(ScannerPlugin):

    """This plugin passes suspects to a clam daemon. 

Actions: This plugin will delete infected messages. If clamd is not reachable or times out, messages can be DEFERRED.

Prerequisites: You must have clamd installed (for performance reasons I recommend it to be on the same box, but this is not absoluely necessary)

Notes for developers:


Tags:

 * sets ``virus['ClamAV']`` (boolean)
 * sets ``ClamavPlugin.virus`` (list of strings) - virus names found in message
"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {
            'host': {
                'default': 'localhost',
                'description': 'hostname where clamd runs',
            },

            'port': {
                'default': '3310',
                'description': "tcp port number or path to clamd.sock for unix domain sockets\nexample /var/lib/clamav/clamd.sock or on ubuntu: /var/run/clamav/clamd.ctl ",
            },

            'timeout': {
                'default': '30',
                'description': 'socket timeout',
            },

            'pipelining': {
                'default': '0',
                'description': "*EXPERIMENTAL*: Perform multiple scans over the same connection. May improve performance on busy systems.",
            },

            'maxsize': {
                'default': '22000000',
                'description': "maximum message size, larger messages will not be scanned.  \nshould match the 'StreamMaxLength' config option in clamd.conf ",
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
        }
        self.logger = self._logger()

    def __str__(self):
        return "Clam AV"

    def _problemcode(self):
        retcode = string_to_actioncode(
            self.config.get(self.section, 'problemaction'), self.config)
        if retcode != None:
            return retcode
        else:
            # in case of invalid problem action
            return DEFER

    def examine(self, suspect):

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
                    suspect.tags['virus']['ClamAV'] = True
                    suspect.tags['ClamavPlugin.virus'] = viruses
                    suspect.debug('viruses found in message : %s' % viruses)
                else:
                    suspect.tags['virus']['ClamAV'] = False

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
                self.__invalidate_socket()

                # don't warn the first time if it's just a broken pipe which
                # can happen with the new pipelining protocol
                if not (i == 0 and isinstance(e, socket.error) and e.errno == errno.EPIPE):
                    self.logger.warning("Error encountered while contacting clamd (try %s of %s): %s" % (
                        i + 1, self.config.getint(self.section, 'retries'), str(e)))

        self.logger.error("Clamdscan failed after %s retries" %
                          self.config.getint(self.section, 'retries'))
        content = None
        return self._problemcode()

    def scan_stream(self, buff):
        """
        Scan byte buffer

        return either :
          - (dict) : {filename1: "virusname"}
          - None if no virus found
          - raises Exception if something went wrong
        """
        pipelining = self.config.getboolean(self.section, 'pipelining')
        s = self.__init_socket__(oneshot=not pipelining)
        s.sendall('zINSTREAM\0')
        default_chunk_size = 2048
        remainingbytes = buff

        while len(remainingbytes) > 0:
            chunklength = min(default_chunk_size, len(remainingbytes))
            #self.logger.debug('sending %s byte chunk' % chunklength)
            chunkdata = remainingbytes[:chunklength]
            remainingbytes = remainingbytes[chunklength:]
            s.sendall(struct.pack('!L', chunklength))
            s.sendall(chunkdata)
        s.sendall(struct.pack('!L', 0))
        dr = {}

        result = self._read_until_delimiter(s).strip()

        if result.startswith('INSTREAM size limit exceeded'):
            raise Exception(
                "Clamd size limit exeeded. Make sure fuglu's clamd maxsize config is not larger than clamd's StreamMaxLength")
        if result.startswith('UNKNOWN'):
            raise Exception(
                "Clamd doesn't understand INSTREAM command. very old version?")

        if pipelining:
            try:
                ans_id, filename, virusinfo = result.split(':', 2)
                filename = filename.strip()
                virusinfo = virusinfo.strip()
            except:
                raise Exception(
                    "Protocol error, could not parse result: %s" % result)

            threadLocal.expectedID += 1
            if threadLocal.expectedID != int(ans_id):
                raise Exception(
                    "Commands out of sync - expected ID %s - got %s" % (threadLocal.expectedID, ans_id))

            if virusinfo[-5:] == 'ERROR':
                raise Exception(virusinfo)
            elif virusinfo != 'OK':
                dr[filename] = virusinfo.replace(" FOUND", '')

            if threadLocal.expectedID >= MAX_SCANS_PER_SOCKET:
                try:
                    s.sendall('zEND\0')
                    s.close()
                finally:
                    self.__invalidate_socket()
        else:
            filename, virusinfo = result.split(':', 1)
            filename = filename.strip()
            virusinfo = virusinfo.strip()
            if virusinfo[-5:] == 'ERROR':
                raise Exception(virusinfo)
            elif virusinfo != 'OK':
                dr[filename] = virusinfo.replace(" FOUND", '')
            s.close()

        if dr == {}:
            return None
        else:
            return dr

    def _read_until_delimiter(self, socket):
        data = ''
        while True:
            chunk = socket.recv(4096)
            if len(chunk) == 0:
                continue
            data += chunk
            if chunk.endswith('\0'):
                break
            if '\0' in chunk:
                raise Exception(
                    "Protocol error: got unexpected additional data after delimiter")
        return data[:-1]  # remove \0 at the end

    def __invalidate_socket(self):
        threadLocal.clamdsocket = None
        threadLocal.expectedID = 0

    def __init_socket__(self, oneshot=False):
        """initialize a socket connection to clamd using host/port/file defined in the configuration
        this connection is initialized with clamd's "IDSESSION" and cached per thread

         set oneshot=True to get a socket without caching it and without initializing it with an IDSESSION
         """

        existing_socket = getattr(threadLocal, 'clamdsocket', None)

        socktimeout = self.config.getint(self.section, 'timeout')

        if existing_socket != None and not oneshot:
            existing_socket.settimeout(socktimeout)
            return existing_socket

        clamd_HOST = self.config.get(self.section, 'host')
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
            s.settimeout(socktimeout)
            try:
                s.connect(sock)
            except socket.error:
                raise Exception(
                    'Could not reach clamd using unix socket %s' % sock)
        else:
            clamd_PORT = int(self.config.get(self.section, 'port'))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(socktimeout)
            try:
                s.connect((clamd_HOST, clamd_PORT))
            except socket.error:
                raise Exception(
                    'Could not reach clamd using network (%s, %s)' % (clamd_HOST, clamd_PORT))

        # initialize an IDSESSION
        if not oneshot:
            s.sendall('zIDSESSION\0')
            threadLocal.clamdsocket = s
            threadLocal.expectedID = 0
        return s

    def lint(self):
        viract = self.config.get(self.section, 'virusaction')
        print("Virusaction: %s" % actioncode_to_string(
            string_to_actioncode(viract, self.config)))
        allok = (self.checkConfig() and self.lint_ping() and self.lint_eicar())
        return allok

    def lint_ping(self):
        try:
            s = self.__init_socket__(oneshot=True)
        except Exception as e:
            print("Could not contact clamd: %s" % (str(e)))
            return False
        s.sendall('PING')
        result = s.recv(20000)
        print("Got Pong: %s" % result)
        if result.strip() != 'PONG':
            print("Invalid PONG:" % result)
        return True

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
        print("Clamav found virus", result)
        return True
