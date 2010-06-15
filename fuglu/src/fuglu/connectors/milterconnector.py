#   Copyright 2010 Oli Schacher
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
# $Id$
#


import logging
import struct
import binascii
import traceback

from fuglu.lib.ppymilterbase import PpyMilter,PpyMilterDispatcher,PpyMilterCloseConnection

from fuglu.scansession import SessionHandler
from fuglu.shared import Suspect
from fuglu.protocolbase import ProtocolHandler,BasicTCPServer


MILTER_LEN_BYTES = 4  # from sendmail's include/libmilter/mfdef.h
class MilterHandler(ProtocolHandler):
    protoname= 'MILTER V2'

    def __init__(self,socket,config):
        ProtocolHandler.__init__(self,socket, config)
        self.sess=MilterSession(socket,config)

    def get_suspect(self):
        succ=self.sess.getincomingmail()
        if not succ:
            self.logger.error('MILTER SESSION NOT COMPLETED')
            return None
        
        #TODO: check success

        sess=self.sess
        fromaddr=sess.from_address
        toaddr=sess.to_address
        tempfilename=sess.tempfilename

        suspect=Suspect(fromaddr,toaddr,tempfilename)
        suspect.recipients=set(sess.recipients)
        return suspect

class MilterSession(PpyMilter):
    def __init__(self,socket,config):
        PpyMilter.__init__(self)
        self.socket=socket
        self.config=config
        self.CanAddHeaders()
        self.CanChangeBody()
        self.CanChangeHeaders()

        self.logger=logging.getLogger('fuglu.miltersession')
        
        self.__milter_dispatcher = PpyMilterDispatcher(self)
        self.body=None
        self.recipients=[]
        self.from_address=None
        self.to_address=None

        #TODO: write msg...
        self.tempfilename=None

    def OnRcptTo(self,cmd,rcpt_to,esmtp_info):
        self.recipients.append(rcpt_to)
        self.to_address=rcpt_to
        return self.Continue()

    def OnMailFrom(self,cmd,mail_from,args):
        self.from_address=mail_from
        return self.Continue()
        
    def OnBody(self, cmd, data):
        self.body=data
        return self.Continue()

    def OnResetState(self):
        self.body=None
        self.recipients=None
        
        
    
    def getincomingmail(self):
        try:
            while True:
                lenbuf=[]
                lenread=0
                while lenread < MILTER_LEN_BYTES:
                    pdat=self.socket.recv(MILTER_LEN_BYTES-lenread)
                    lenbuf.append(pdat)
                    lenread+=len(pdat)
                dat="".join(lenbuf)
                self.logger.info(dat)
                self.logger.info(len(dat))
                packetlen = int(struct.unpack('!I',dat)[0])
                inbuf = []
                read = 0
                while read < packetlen:
                    partial_data = self.socket.recv(packetlen - read)
                    inbuf.append(partial_data)
                    read += len(partial_data)
                data = "".join(inbuf)
                self.logger.debug('  <<< %s', binascii.b2a_qp(data))
                try:
                    response = self.__milter_dispatcher.Dispatch(data)
                    if type(response) == list:
                        for r in response:
                            self.__send_response(r)
                    elif response:
                        self.__send_response(response)
                except PpyMilterCloseConnection, e:
                    #logging.info('Closing connection ("%s")', str(e))
                    break
        except Exception,e:
            exc=traceback.format_exc()
            self.logger.error('Exception in MilterSession: %s %s'%(e,exc))
            return False
        return True

    def __send_response(self, response):
        """Send data down the milter socket.

        Args:
          response: the data to send
        """
        self.logger.debug('  >>> %s', binascii.b2a_qp(response[0]))
        self.socket.send(struct.pack('!I', len(response)))
        self.socket.send(response)

class MilterServer(BasicTCPServer):
    def __init__(self, controller,port=10125,address="127.0.0.1"):
        BasicTCPServer.__init__(self, controller, port, address, MilterHandler)
