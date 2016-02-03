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

import smtplib
import logging
import socket
import string
import tempfile
import os
import unittest
import re

from fuglu.shared import Suspect, apply_template
from fuglu.protocolbase import ProtocolHandler, BasicTCPServer
from email.header import Header


def buildmsgsource(suspect):
    """Build the message source with fuglu headers prepended"""

    # we must prepend headers manually as we can't set a header order in email
    # objects
    origmsgtxt = suspect.get_source()
    newheaders = ""

    for key in suspect.addheaders:
        # is ignore the right thing to do here?
        val = suspect.addheaders[key]
        val.encode('UTF-8', 'ignore')
        #self.logger.debug('Adding header %s : %s'%(key,val))
        hdr = Header(val, header_name=key, continuation_ws=' ')
        newheaders += "%s: %s\n" % (key, hdr.encode())

    modifiedtext = newheaders + origmsgtxt
    return modifiedtext


class SMTPHandler(ProtocolHandler):
    protoname = 'SMTP (After Queue)'

    def __init__(self, socket, config):
        ProtocolHandler.__init__(self, socket, config)
        self.sess = SMTPSession(socket, config)

    def is_signed(self, suspect):
        msgrep = suspect.get_message_rep()
        if 'Content-Type' in msgrep:
            ctype = msgrep['Content-Type'].lower()
            if 'multipart/signed' in ctype or 'application/pkcs7-mime' in ctype:
                return True
        return False

    def re_inject(self, suspect):
        """Send message back to postfix"""
        if suspect.get_tag('noreinject'):
            return 'message not re-injected by plugin request'

        if suspect.get_tag('reinjectoriginal'):
            self.logger.info(
                '%s: Injecting original message source without modifications' % suspect.id)
            msgcontent = suspect.get_original_source()
        elif self.is_signed(suspect):
            self.logger.info(
                '%s: S/MIME signed message detected - sending original source without modifications' % suspect.id)
            msgcontent = suspect.get_original_source()
        else:
            msgcontent = buildmsgsource(suspect)

        targethost = self.config.get('main', 'outgoinghost')
        if targethost == '${injecthost}':
            targethost = self.socket.getpeername()[0]
        client = FUSMTPClient(
            targethost, self.config.getint('main', 'outgoingport'))
        helo = self.config.get('main', 'outgoinghelo')
        if helo.strip() == '':
            helo = socket.gethostname()
        client.helo(helo)

        client.sendmail(suspect.from_address, suspect.recipients, msgcontent)
        # if we did not get an exception so far, we can grab the server answer using the patched client
        # servercode=client.lastservercode
        serveranswer = client.lastserveranswer
        try:
            client.quit()
        except Exception as e:
            self.logger.warning(
                'Exception while quitting re-inject session: %s' % str(e))

        if serveranswer == None:
            self.logger.warning('Re-inject: could not get server answer.')
            serveranswer = ''
        return serveranswer

    def get_suspect(self):
        success = self.sess.getincomingmail()
        if not success:
            self.logger.error('incoming smtp transfer did not finish')
            return None

        sess = self.sess
        fromaddr = sess.from_address
        toaddr = sess.to_address
        tempfilename = sess.tempfilename

        suspect = Suspect(fromaddr, toaddr, tempfilename)
        suspect.recipients = set(sess.recipients)
        return suspect

    def commitback(self, suspect):
        injectanswer = self.re_inject(suspect)
        suspect.set_tag("injectanswer", injectanswer)
        values = dict(injectanswer=injectanswer)
        message = apply_template(
            self.config.get('smtpconnector', 'requeuetemplate'), suspect, values)

        self.sess.endsession(250, message)
        self.sess = None

    def defer(self, reason):
        self.sess.endsession(451, reason)

    def discard(self, reason):
        self.sess.endsession(250, reason)
        # self.sess=None

    def reject(self, reason):
        self.sess.endsession(550, reason)


class FUSMTPClient(smtplib.SMTP):

    """
    This class patches the sendmail method of SMTPLib so we can get the return message from postfix
    after we have successfully re-injected. We need this so we can find out the new Queue-ID
    """

    def getreply(self):
        (code, response) = smtplib.SMTP.getreply(self)
        self.lastserveranswer = response
        self.lastservercode = code
        return (code, response)


class SMTPServer(BasicTCPServer):

    def __init__(self, controller, port=10125, address="127.0.0.1"):
        BasicTCPServer.__init__(self, controller, port, address, SMTPHandler)


class SMTPSession(object):
    ST_INIT = 0
    ST_HELO = 1
    ST_MAIL = 2
    ST_RCPT = 3
    ST_DATA = 4
    ST_QUIT = 5

    def __init__(self, socket, config):
        self.config = config
        self.from_address = None
        self.to_address = None  # single address
        self.recipients = []  # multiple recipients
        self.helo = None

        self.socket = socket
        self.state = SMTPSession.ST_INIT
        self.logger = logging.getLogger("fuglu.smtpsession")
        self.tempfile = None

    def endsession(self, code, message):
        self.socket.send("%s %s\r\n" % (code, message))
        data = ''
        completeLine = 0
        while not completeLine:
            lump = self.socket.recv(1024)
            if len(lump):
                data += lump
                if (len(data) >= 2) and data[-2:] == '\r\n':
                    completeLine = 1
                    cmd = data[0:4]
                    cmd = string.upper(cmd)
                    keep = 1
                    rv = None
                    if cmd == "QUIT":
                        self.socket.send("%s %s\r\n" % (220, "BYE"))
                        self.closeconn()
                        return
                    self.socket.send(
                        "%s %s\r\n" % (421, "Cannot accept further commands"))
                    self.closeconn()
                    return
            else:
                self.closeconn()
                return
        return

    def closeconn(self):
        self.socket.close()

    def getincomingmail(self):
        """return true if mail got in, false on error Session will be kept open"""
        self.socket.send("220 fuglu scanner ready \r\n")
        while 1:
            data = ''
            completeLine = 0
            while not completeLine:
                lump = self.socket.recv(1024)
                if len(lump):
                    data += lump
                    if (len(data) >= 2) and data[-2:] == '\r\n':
                        completeLine = 1
                        if self.state != SMTPSession.ST_DATA:
                            rsp, keep = self.doCommand(data)
                        else:
                            try:
                                rsp = self.doData(data)
                            except IOError:
                                self.endsession(
                                    421, "Could not write to temp file")
                                return False

                            if rsp == None:
                                continue
                            else:
                                # data finished.. keep connection open though
                                self.logger.debug('incoming message finished')
                                return True

                        self.socket.send(rsp + "\r\n")
                        if keep == 0:
                            self.socket.close()
                            return False
                else:
                    # EOF
                    return False
        return False

    def doCommand(self, data):
        """Process a single SMTP Command"""
        cmd = data[0:4]
        cmd = string.upper(cmd)
        keep = 1
        rv = None
        if cmd == "HELO":
            self.state = SMTPSession.ST_HELO
            self.helo = data
        elif cmd == "RSET":
            self.from_address = None
            self.to_address = None
            self.helo = None
            self.dataAccum = ""
            self.state = SMTPSession.ST_INIT
        elif cmd == "NOOP":
            pass
        elif cmd == "QUIT":
            keep = 0
        elif cmd == "MAIL":
            if self.state != SMTPSession.ST_HELO:
                return ("503 Bad command sequence", 1)
            self.state = SMTPSession.ST_MAIL
            self.from_address = self.stripAddress(data)
        elif cmd == "RCPT":
            if (self.state != SMTPSession.ST_MAIL) and (self.state != SMTPSession.ST_RCPT):
                return ("503 Bad command sequence", 1)
            self.state = SMTPSession.ST_RCPT
            rec = self.stripAddress(data)
            self.to_address = rec
            self.recipients.append(rec)
        elif cmd == "DATA":
            if self.state != SMTPSession.ST_RCPT:
                return ("503 Bad command sequence", 1)
            self.state = SMTPSession.ST_DATA
            self.dataAccum = ""
            try:
                (handle, tempfilename) = tempfile.mkstemp(
                    prefix='fuglu', dir=self.config.get('main', 'tempdir'))
                self.tempfilename = tempfilename
                self.tempfile = os.fdopen(handle, 'w+b')
            except Exception as e:
                self.endsession(421, "could not create file: %s" % str(e))

            return ("354 OK, Enter data, terminated with a \\r\\n.\\r\\n", 1)
        else:
            return ("505 Eh? WTF was that?", 1)

        if rv:
            return (rv, keep)
        else:
            return("250 OK", keep)

    def doData(self, data):
        data = self.unquoteData(data)
        # store the last few bytes in memory to keep track when the msg is
        # finished
        self.dataAccum = self.dataAccum + data

        if len(self.dataAccum) > 4:
            self.dataAccum = self.dataAccum[-5:]

        if len(self.dataAccum) > 4 and self.dataAccum[-5:] == '\r\n.\r\n':
            # check if there is more data to write to the file
            if len(data) > 4:
                self.tempfile.write(data[0:-5])

            self.tempfile.close()

            self.state = SMTPSession.ST_HELO
            return "250 OK - Data and terminator. found"
        else:
            self.tempfile.write(data)
            return None

    def unquoteData(self, data):
        """two leading dots at the beginning of a line must be unquoted to a single dot"""
        return re.sub(r'(?m)^\.\.', '.', data)

    def stripAddress(self, address):
        """
        Strip the leading & trailing <> from an address.  Handy for
        getting FROM: addresses.
        """
        start = address.find('<') + 1
        if start < 1:
            start = address.find(':') + 1
        if start < 1:
            raise ValueError("Could not parse address %s" % address)
        end = string.find(address, '>')
        if end < 0:
            end = len(address)
        retaddr = address[start:end]
        retaddr = retaddr.strip()
        return retaddr
