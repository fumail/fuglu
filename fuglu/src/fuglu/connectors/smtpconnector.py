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

import smtplib
import logging
import socket
import string
import tempfile
import os
import re
import sys

from fuglu.shared import Suspect, apply_template
from fuglu.protocolbase import ProtocolHandler, BasicTCPServer
from email.header import Header
from fuglu.encodings import force_bString, force_uString


def buildmsgsource(suspect):
    """Build the message source with fuglu headers prepended"""

    # we must prepend headers manually as we can't set a header order in email
    # objects
    origmsgtxt = suspect.get_source()
    newheaders = ""

    for key in suspect.addheaders:
        # is ignore the right thing to do here?
        val = suspect.addheaders[key]
        #self.logger.debug('Adding header %s : %s'%(key,val))
        hdr = Header(val, header_name=key, continuation_ws=' ')
        try:
            newheaders += "%s: %s\n" % (key, hdr.encode())
        except Exception as e:
            from inspect import currentframe, getframeinfo
            frameinfo = getframeinfo(currentframe())
            logger = logging.getLogger("fuglu.buildmsgsource")
            logger.error("%s:%s %s" % (frameinfo.filename, frameinfo.lineno,str(e)))
            raise e

    modifiedtext = newheaders + origmsgtxt
    return modifiedtext


class SMTPHandler(ProtocolHandler):
    protoname = 'SMTP (after queue)'

    def __init__(self, socket, config):
        ProtocolHandler.__init__(self, socket, config)
        self.sess = SMTPSession(socket, config)

    def re_inject(self, suspect):
        """Send message back to postfix"""
        if suspect.get_tag('noreinject'):
            return 'message not re-injected by plugin request'

        if suspect.get_tag('reinjectoriginal'):
            self.logger.info(
                '%s: Injecting original message source without modifications' % suspect.id)
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

        if serveranswer is None:
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
        tempfilename = sess.tempfilename

        try:
            suspect = Suspect(fromaddr, sess.recipients, tempfilename)
        except ValueError as e:
            if len(sess.recipients)>0:
                toaddr = sess.recipients[0]
            else:
                toaddr = ''
            self.logger.error('failed to initialise suspect with from=<%s> to=<%s> : %s' % (fromaddr, toaddr, str(e)))
            raise
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

    def reject(self, reason):
        self.sess.endsession(550, reason)


class FUSMTPClient(smtplib.SMTP):

    """
    This class patches the sendmail method of SMTPLib so we can get the return message from postfix
    after we have successfully re-injected. We need this so we can find out the new Queue-ID
    """

    def getreply(self):
        code, response = smtplib.SMTP.getreply(self)
        self.lastserveranswer = response
        self.lastservercode = code
        return code, response


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
        self.recipients = []
        self.helo = None
        self.dataAccum = None

        self.socket = socket
        self.state = SMTPSession.ST_INIT
        self.logger = logging.getLogger("fuglu.smtpsession")
        self.tempfilename = None
        self.tempfile = None
        self._noisy = True

    def endsession(self, code, message):
        try:
            if self._noisy:
                self.logger.debug("endsession - send message: \"%s\" and code: \"%s\"" % (str(message),str(code)))

            self.socket.send(force_bString("%s %s\r\n" % (code, message)))
            if self._noisy:
                self.logger.debug("endsession - sent message and code")
        except Exception as e:
            from inspect import currentframe, getframeinfo
            frameinfo = getframeinfo(currentframe())
            self.logger.error("%s:%s %s" % (frameinfo.filename, frameinfo.lineno,str(e)))
            raise e
        rawdata = b''
        completeLine = 0
        while not completeLine:
            lump = self.socket.recv(1024)
            if self._noisy:
                self.logger.debug("endsession - after receiving 1024 bytes")

            if len(lump):
                if self._noisy:
                    self.logger.debug("endsession - adding lump to rawdata")

                rawdata += lump
                if (len(rawdata) >= 2) and rawdata[-2:] == force_bString('\r\n'):
                    completeLine = 1
                    cmd = rawdata[0:4]
                    cmd = cmd.upper()
                    keep = 1
                    rv = None
                    if cmd == force_bString("QUIT"):
                        if self._noisy:
                            self.logger.debug("endsession - QUIT command - send 220")
                        try:
                            self.socket.send(force_bString("%s %s\r\n" % (220, "BYE")))
                        except Exception as e:
                            from inspect import currentframe, getframeinfo
                            frameinfo = getframeinfo(currentframe())
                            self.logger.error("%s:%s %s" % (frameinfo.filename, frameinfo.lineno,str(e)))
                            raise e
                        self.closeconn()
                        return
                    try:
                        if self._noisy:
                            self.logger.debug("endsession - send 421, command is %" % force_uString(cmd))
                        self.socket.send( force_bString("%s %s\r\n" % (421, "Cannot accept further commands")))
                    except Exception as e:
                        from inspect import currentframe, getframeinfo
                        frameinfo = getframeinfo(currentframe())
                        self.logger.error("%s:%s %s" % (frameinfo.filename, frameinfo.lineno,str(e)))
                        raise e
                    self.closeconn()
                    return
            else:
                if self._noisy:
                    self.logger.debug("endsession - lump length is zero -> ending session")
                self.closeconn()
                return
        if self._noisy:
           self.logger.debug("endsession - end of function return statement reached")
        return

    def closeconn(self):
        if sys.version_info > (3,):
            self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

    def _close_tempfile(self):
        if self.tempfile and not self.tempfile.closed:
            self.tempfile.close()

    def getincomingmail(self):
        """return true if mail got in, false on error Session will be kept open"""
        try:
            if self._noisy:
                self.logger.debug("getincomingmail - send ready string")
            self.socket.send(force_bString("220 fuglu scanner ready \r\n"))
            if self._noisy:
                self.logger.debug("getincomingmail - after sending ready string")
        except Exception as e:
            from inspect import currentframe, getframeinfo
            frameinfo = getframeinfo(currentframe())
            self.logger.error("%s:%s %s" % (frameinfo.filename, frameinfo.lineno,str(e)))
            raise e

        while True:
            rawdata = b''
            data = ''
            completeLine = 0
            while not completeLine:
                if self._noisy:
                    self.logger.debug("getincomingmail - waiting to receive 1025 bytes...")

                lump = self.socket.recv(1024)
                if self._noisy:
                    self.logger.debug("getincomingmail - after receiving 1024 bytes, lenth of lump is %d" % (len(lump)))

                if len(lump):
                    rawdata += lump

                    if self._noisy:
                        self.logger.debug("getincomingmail - length of rawdata is %d" % (len(rawdata)))

                    if (len(rawdata) >= 2) and rawdata[-2:] == force_bString('\r\n'):
                        completeLine = 1

                        if self._noisy:
                            self.logger.debug("getincomingmail - line is complete")
                            self.logger.debug("getincomingmail - state = %s" % (self.state))

                        if self.state != SMTPSession.ST_DATA:
                            if self._noisy:
                                self.logger.debug("getincomingmail - running doCommand")

                            # convert data to unicode if needed
                            data = force_uString(rawdata)
                            rsp, keep = self.doCommand(data)

                            if self._noisy:
                                self.logger.debug("getincomingmail - doCommand -> response rsp=%s, keep=%s" % (str(rsp),str(keep)))
                        else:
                            try:
                                if self._noisy:
                                    self.logger.debug("getincomingmail - running doData")
                                #directly use raw bytes-string data
                                rsp = self.doData(rawdata)
                                if self._noisy:
                                    self.logger.debug("getincomingmail - doData -> response rsp=%s" % (str(rsp)))
                            except IOError:
                                if self._noisy:
                                    self.logger.debug("getincomingmail - IOError")

                                self.endsession(
                                    421, "Could not write to temp file")
                                self._close_tempfile()
                                return False

                            if rsp is None:
                                if self._noisy:
                                    self.logger.debug("getincomingmail - rsp is None -> continue")
                                continue
                            else:
                                # data finished.. keep connection open though
                                if self._noisy:
                                    self.logger.debug('incoming message finished')
                                return True

                        try:
                            if self._noisy:
                                self.logger.debug("getincomingmail - send response: %s" % (str(rsp)))

                            self.socket.send(force_bString(rsp + "\r\n"))
                        except Exception as e:
                            from inspect import currentframe, getframeinfo
                            frameinfo = getframeinfo(currentframe())
                            self.logger.error("%s:%s %s" % (frameinfo.filename, frameinfo.lineno,str(e)))
                            raise e
                        if keep == 0:
                            if self._noisy:
                                self.logger.debug("getincomingmail - keep = 0 -> close connection and return False")

                            self.closeconn()
                            return False
                else:
                    # EOF
                    if self._noisy:
                        self.logger.debug("getincomingmail -> EOF -> Return False")
                    return False
        if self._noisy:
            self.logger.debug("getincomingmail -> End of routine -> Return False")
        return False

    def doCommand(self, data):
        """Process a single SMTP Command"""
        cmd = data[0:4]
        cmd = cmd.upper()
        keep = 1
        rv = None
        if cmd == "HELO":
            self.state = SMTPSession.ST_HELO
            self.helo = data
        elif cmd == "RSET":
            self.from_address = None
            self.recipients = []
            self.helo = None
            self.dataAccum = ""
            self.state = SMTPSession.ST_INIT
        elif cmd == "NOOP":
            pass
        elif cmd == "QUIT":
            keep = 0
        elif cmd == "MAIL":
            if self.state != SMTPSession.ST_HELO:
                return "503 Bad command sequence", 1
            self.state = SMTPSession.ST_MAIL
            self.from_address = self.stripAddress(data)
        elif cmd == "RCPT":
            if (self.state != SMTPSession.ST_MAIL) and (self.state != SMTPSession.ST_RCPT):
                return "503 Bad command sequence", 1
            self.state = SMTPSession.ST_RCPT
            rec = self.stripAddress(data)
            self.recipients.append(rec)
        elif cmd == "DATA":
            if self.state != SMTPSession.ST_RCPT:
                return "503 Bad command sequence", 1
            self.state = SMTPSession.ST_DATA
            self.dataAccum = b""
            try:
                (handle, tempfilename) = tempfile.mkstemp(
                    prefix='fuglu', dir=self.config.get('main', 'tempdir'))
                self.tempfilename = tempfilename
                self.tempfile = os.fdopen(handle, 'w+b')
            except Exception as e:
                self.endsession(421, "could not create file: %s" % str(e))
                self._close_tempfile()

            return "354 OK, Enter data, terminated with a \\r\\n.\\r\\n", 1
        else:
            return "505 Eh? WTF was that?", 1

        if rv:
            return rv, keep
        else:
            return "250 OK", keep

    def doData(self, data):
        """Store data in temporary file

        Args:
            data (): data as byte-string

        """
        data = self.unquoteData(data)
        # store the last few bytes in memory to keep track when the msg is
        # finished
        self.dataAccum = self.dataAccum + data

        if len(self.dataAccum) > 4:
            self.dataAccum = self.dataAccum[-5:]

        if len(self.dataAccum) > 4 and self.dataAccum[-5:] == force_bString('\r\n.\r\n'):
            # check if there is more data to write to the file
            if len(data) > 4:
                self.tempfile.write(data[0:-5])

            self._close_tempfile()

            self.state = SMTPSession.ST_HELO
            return "250 OK - Data and terminator. found"
        else:
            self.tempfile.write(data)
            return None

    def unquoteData(self, data):
        """two leading dots at the beginning of a line must be unquoted to a single dot"""
        return re.sub(b'(?m)^\.\.', b'.', force_bString(data))

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
        end = address.find('>')
        if end < 0:
            end = len(address)
        retaddr = address[start:end]
        retaddr = retaddr.strip()
        return retaddr
