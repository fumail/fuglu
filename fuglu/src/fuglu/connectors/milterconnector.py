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


import logging
import struct
import binascii
import traceback

from fuglu.lib.ppymilterbase import PpyMilter, PpyMilterDispatcher, PpyMilterCloseConnection, SMFIC_BODYEOB, RESPONSE

from fuglu.shared import Suspect
from fuglu.protocolbase import ProtocolHandler, BasicTCPServer
import tempfile
import os

MILTER_LEN_BYTES = 4  # from sendmail's include/libmilter/mfdef.h


class MilterHandler(ProtocolHandler):
    protoname = 'MILTER V2'

    def __init__(self, socket, config):
        ProtocolHandler.__init__(self, socket, config)
        self.sess = MilterSession(socket, config)

    def get_suspect(self):
        succ = self.sess.getincomingmail()
        if not succ:
            self.logger.error('MILTER SESSION NOT COMPLETED')
            return None

        sess = self.sess
        fromaddr = sess.from_address
        toaddr = sess.to_address
        tempfilename = sess.tempfilename
        suspect = Suspect(fromaddr, toaddr, tempfilename)
        suspect.recipients = set(sess.recipients)

        if sess.helo is not None and sess.addr is not None and sess.rdns is not None:
            suspect.clientinfo = sess.helo, sess.addr, sess.rdns

        return suspect

    def commitback(self, suspect):
        self.sess.answer = self.sess.Continue()
        self.sess.finish()
        self.sess = None

    def defer(self, reason):
        # apparently milter wants extended status codes (at least
        # milter-test-server does)
        if not reason.startswith("4."):
            reason = "4.7.1 %s" % reason
        # self.logger.info("Defer...%s"%reason)
        self.sess.answer = self.sess.CustomReply(450, reason)
        self.sess.finish()
        self.sess = None

    def reject(self, reason):
        # apparently milter wants extended status codes (at least
        # milter-test-server does)
        if not reason.startswith("5."):
            reason = "5.7.1 %s" % reason
        # self.logger.info("reject...%s"%reason)
        self.sess.answer = self.sess.CustomReply(550, reason)
        self.sess.finish()
        self.sess = None

    def discard(self, reason):
        self.sess.answer = self.sess.Discard()
        self.sess.finish()
        self.sess = None


class MilterSession(PpyMilter):

    def __init__(self, socket, config):
        PpyMilter.__init__(self)
        self.socket = socket
        self.config = config
        self.CanAddHeaders()
        self.CanChangeBody()
        self.CanChangeHeaders()

        self.logger = logging.getLogger('fuglu.miltersession')

        self.__milter_dispatcher = PpyMilterDispatcher(self)
        self.recipients = []
        self.from_address = None
        self.to_address = None

        (handle, tempfilename) = tempfile.mkstemp(
            prefix='fuglu', dir=self.config.get('main', 'tempdir'))
        self.tempfilename = tempfilename
        self.tempfile = os.fdopen(handle, 'w+b')

        self.currentmilterdata = None

        self.answer = self.Continue()

        self.helo = None
        self.ip = None
        self.rdns = None

    def OnConnect(self, cmd, hostname, family, port, address):
        if family not in ('4', '6'):  # we don't handle unix socket
            return self.Continue()
        if hostname is None or hostname == '[%s]' % address:
            hostname = 'unknown'

        self.rdns = hostname
        self.addr = address
        return self.Continue()

    def OnHelo(self, cmd, helo):
        self.helo = helo
        return self.Continue()

    def OnRcptTo(self, cmd, rcpt_to, esmtp_info):
        self.recipients.append(rcpt_to)
        self.to_address = rcpt_to
        return self.Continue()

    def OnMailFrom(self, cmd, mail_from, args):
        self.from_address = mail_from
        return self.Continue()

    def OnHeader(self, cmd, header, value):
        self.tempfile.write("%s: %s\n" % (header, value))
        return self.Continue()

    def OnEndHeaders(self, cmd):
        self.tempfile.write("\n")
        return self.Continue()

    def OnBody(self, cmd, data):
        self.tempfile.write(data)
        return self.Continue()

    def OnEndBody(self, cmd):
        return self.answer

    def OnResetState(self):
        self.recipients = None
        self.tempfile = None
        self.tempfilename = None

    def _read_milter_command(self):
        lenbuf = []
        lenread = 0
        while lenread < MILTER_LEN_BYTES:
            pdat = self.socket.recv(MILTER_LEN_BYTES - lenread)
            lenbuf.append(pdat)
            lenread += len(pdat)
        dat = "".join(lenbuf)
        # self.logger.info(dat)
        # self.logger.info(len(dat))
        packetlen = int(struct.unpack('!I', dat)[0])
        inbuf = []
        read = 0
        while read < packetlen:
            partial_data = self.socket.recv(packetlen - read)
            inbuf.append(partial_data)
            read += len(partial_data)
        data = "".join(inbuf)
        return data

    def finish(self):
        """we assume to be at SMFIC_BODYEOB"""
        try:
            while True:
                if self.currentmilterdata != None:
                    data = self.currentmilterdata
                    self.currentmilterdata = None
                else:
                    data = self._read_milter_command()
                try:
                    response = self.__milter_dispatcher.Dispatch(data)
                    if type(response) == list:
                        for r in response:
                            self.__send_response(r)
                    elif response:
                        self.__send_response(response)
                except PpyMilterCloseConnection as e:
                    #logging.info('Closing connection ("%s")', str(e))
                    break
        except Exception as e:
            # TODO: here we get broken pipe if we're not using self.Continue(), but the milter client seems happy
            # so, silently discarding this exception for now
            pass

    def getincomingmail(self):
        try:
            while True:
                data = self._read_milter_command()
                self.currentmilterdata = data
                (cmd, args) = (data[0], data[1:])
                if cmd == SMFIC_BODYEOB:
                    self.tempfile.close()
                    return True
                try:
                    response = self.__milter_dispatcher.Dispatch(data)
                    if type(response) == list:
                        for r in response:
                            self.__send_response(r)
                    elif response:
                        self.__send_response(response)
                except PpyMilterCloseConnection as e:
                    #logging.info('Closing connection ("%s")', str(e))
                    break
        except Exception as e:
            exc = traceback.format_exc()
            self.logger.error('Exception in MilterSession: %s %s' % (e, exc))
            return False
        return False

    def __send_response(self, response):
        """Send data down the milter socket.

        Args:
          response: the data to send
        """
        #self.logger.debug('  >>> %s', binascii.b2a_qp(response[0]))
        self.socket.send(struct.pack('!I', len(response)))
        self.socket.send(response)


class MilterServer(BasicTCPServer):

    def __init__(self, controller, port=10125, address="127.0.0.1"):
        BasicTCPServer.__init__(self, controller, port, address, MilterHandler)
