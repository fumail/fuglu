#   Copyright 2009 Oli Schacher
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
# 
import smtplib
import logging
import socket
import sys
import threading
import string
import tempfile
import os
from fuglu.protocolbase import ProtocolHandler
import unittest
import thread
import ConfigParser
from fuglu.scansession import SessionHandler
from fuglu.shared import Suspect

from email.Header import Header


def buildmsgsource(suspect):
    """Build the message source with fuglu headers prepended"""
    #we must prepend headers manually as we can't set a header order in email objects
    
    msgrep=suspect.getMessageRep()
    
    origmsgtxt=msgrep.as_string()
    newheaders=""
    
    for key in suspect.addheaders:
        val=unicode(suspect.addheaders[key],errors='ignore')  # is ignore the right thing to do here?
        #self.logger.debug('Adding header %s : %s'%(key,val))
        hdr=Header(val, header_name=key, continuation_ws=' ')
        newheaders+="%s: %s\n"%(key,hdr.encode())
    
    modifiedtext=newheaders+origmsgtxt
    return modifiedtext


class SMTPHandler(ProtocolHandler):
    def __init__(self,socket,config):
        ProtocolHandler.__init__(self, socket,config)
        self.sess=SMTPSession(socket,config)
    
    
    def re_inject(self,suspect):
        """Send message back to postfix"""
        if suspect.get_tag('noreinject'):
            return 'message not re-injected by plugin request'
        modifiedtext=buildmsgsource(suspect)
        
        client = FUSMTPClient('127.0.0.1',self.config.getint('main', 'outgoingport'))
        client.helo(self.config.get('main','outgoinghelo'))
  
        client.sendmail(suspect.from_address, suspect.to_address, modifiedtext)
        #if we did not get an exception so far, we can grab the server answer using the patched client
        #servercode=client.lastservercode
        serveranswer=client.lastserveranswer
        try:
            client.quit()
        except Exception,e:
            self.logger.warning('Exception while quitting re-inject session: %s'%str(e))
        
        if serveranswer==None:
            self.logger.warning('Re-inject: could not get server answer.')
            serveranswer=''
        return serveranswer
    

    def get_suspect(self):
        success=self.sess.getincomingmail()
        if not success:
            self.logger.error('incoming smtp transfer did not finish')
            return None
        
        sess=self.sess
        fromaddr=sess.from_address
        toaddr=sess.to_address
        tempfilename=sess.tempfilename
        
        suspect=Suspect(fromaddr,toaddr,tempfilename)
        suspect.recipients=set(sess.recipients)
        return suspect

    def commitback(self,suspect):
        injectanswer=self.re_inject(suspect)
        self.sess.endsession(250, "FUGLU REQUEUE(%s): %s"%(suspect.id,injectanswer))
        self.sess=None
        
    def defer(self,reason):
        self.sess.endsession(451, reason)
        
    def discard(self,reason):
        self.sess.endsession(250, "OK")
        #self.sess=None
        
class FUSMTPClient(smtplib.SMTP):

    """
    This class patches the sendmail method of SMTPLib so we can get the return message from postfix 
    after we have successfully re-injected. We need this so we can find out the new Queue-ID
    """
    
    def getreply(self):
        (code,response)=smtplib.SMTP.getreply(self)
        self.lastserveranswer=response
        self.lastservercode=code
        return (code,response)
    

class SMTPServer(object):    
    def __init__(self, controller,port=10025,address="127.0.0.1"):
        self.logger=logging.getLogger("fuglu.smtp.incoming.%s"%(port))
        self.logger.debug('Starting incoming SMTP Server on Port %s'%port)
        self.port=port
        self.controller=controller
        self.stayalive=1
        
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((address, port))
            self._socket.listen(5)
        except Exception,e:
            self.logger.error('Could not start incoming SMTP Server: %s'%e)
            sys.exit(1)
   
   
    def shutdown(self):
        self.stayalive=False
        self._socket.close()
        
    def serve(self):
        #disable to debug... 
        use_multithreading=True
        controller=self.controller
        threading.currentThread().name='SMTP Server on Port %s'%self.port
        
        self.logger.info('SMTP Server running on port %s'%self.port)
        if use_multithreading:
                threadpool=self.controller.threadpool
        while self.stayalive:
            try:
                self.logger.debug('Waiting for connection...')
                nsd = self._socket.accept()
                if not self.stayalive:
                    break
                ph=SMTPHandler(nsd[0], controller.config)
                engine = SessionHandler(ph,controller.config,controller.prependers,controller.plugins,controller.appenders)
                self.logger.debug('Incoming connection from %s'%str(nsd[1]))
                if use_multithreading:
                    #this will block if queue is full
                    threadpool.add_task(engine)
                else:
                    engine.handlesession()
            except Exception,e:
                self.logger.error('Exception in serve(): %s'%str(e))

                 
class ESMTPPassthroughSession(object):
    ST_INIT = 0
    ST_HELO = 1
    ST_MAIL = 2
    ST_RCPT = 3
    ST_DATA = 4
    ST_QUIT = 5
    
    
    def _init_forward_connection(self):
        self.logger.debug('esablisihng pre-q forward connection to postfix')
        HOST = '127.0.0.1'    # The remote host
        PORT = 50007         # The same port as used by the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        s.send('Hello, world')
        data = s.recv(1024)
        s.close()
        print 'Received', repr(data)

    
    def __init__(self, socket,config):
        self.config=config
        self.from_address=None
        self.to_address=None  #single address
        self.recipients=[] #multiple recipients
        self.helo=None
        
        self.socket = socket;
        self.state = SMTPSession.ST_INIT
        self.logger=logging.getLogger("fuglu.smtpsession")
        self.tempfile=None

        #TODO: create client socket here, pass all commands to postfix
        #the handler reinject code should then only pass the data section here?
        self.outsocket=socket.socket()

    def endsession(self,code,message):
        self.socket.send("%s %s\r\n"%(code,message))
        data = ''
        completeLine = 0
        while not completeLine:
            lump = self.socket.recv(1024);
            if len(lump):
                data += lump
                if (len(data) >= 2) and data[-2:] == '\r\n':
                    completeLine = 1
                    cmd = data[0:4]
                    cmd = string.upper(cmd)
                    keep = 1
                    rv = None
                    if cmd == "QUIT":
                        self.socket.send("%s %s\r\n"%(220,"BYE"))
                        self.closeconn()
                        return
                    self.socket.send("%s %s\r\n"%(421,"Cannot accept further commands"))
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
                lump = self.socket.recv(1024);
                if len(lump):
                    data += lump
                    if (len(data) >= 2) and data[-2:] == '\r\n':
                        completeLine = 1
                        if self.state != SMTPSession.ST_DATA:
                            rsp, keep = self.doCommand(data)
                        else:
                            try:
                                rsp=self.doData(data)
                            except IOError:
                                self.endsession(421,"Could not write to temp file")
                                return False
                                
                            if rsp == None:
                                continue
                            else:
                                #data finished.. keep connection open though
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
            self.helo=data
        elif cmd == "RSET":
            self.from_address=None
            self.to_address=None
            self.helo=None
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
            self.from_address=self.stripAddress(data)
        elif cmd == "RCPT":
            if (self.state != SMTPSession.ST_MAIL) and (self.state != SMTPSession.ST_RCPT):
                return ("503 Bad command sequence", 1)
            self.state = SMTPSession.ST_RCPT
            rec=self.stripAddress(data)
            self.to_address=rec
            self.recipients.append(rec)
        elif cmd == "DATA":
            if self.state != SMTPSession.ST_RCPT:
                return ("503 Bad command sequence", 1)
            self.state = SMTPSession.ST_DATA
            self.dataAccum = ""
            try:
                (handle,tempfilename)=tempfile.mkstemp(prefix='fuglu',dir=self.config.get('main','tempdir'))
                self.tempfilename=tempfilename
                self.tempfile=os.fdopen(handle,'w+b')
            except Exception,e:
                self.endsession(421,"could not create file: %s"%str(e))

            return ("354 OK, Enter data, terminated with a \\r\\n.\\r\\n", 1)
        else:
            return ("505 Eh? WTF was that?", 1)

        if rv:
            return (rv, keep)
        else:
            return("250 OK", keep)

    def doData(self, data):
        #store the last few bytes in memory to keep track when the msg is finished
        self.dataAccum = self.dataAccum + data
        
        if len(self.dataAccum)>4:
            self.dataAccum=self.dataAccum[-5:]
        
        if len(self.dataAccum) > 4 and self.dataAccum[-5:] == '\r\n.\r\n':
            #check if there is more data to write tot he file
            if len(data)>4:
                self.tempfile.write(data[0:-5])
            
            self.tempfile.close()

            self.state = SMTPSession.ST_HELO
            return "250 OK - Data and terminator. found"
        else:
            self.tempfile.write(data)
            return None   
             
    def stripAddress(self,address):
        """
        Strip the leading & trailing <> from an address.  Handy for
        getting FROM: addresses.
        """
        start = address.find('<') + 1
        if start<1:
            start=address.find(':')+1
        if start<1:
            raise ValueError,"Could not parse address %s"%address
        end = string.find(address, '>')
        if end<0:
            end=len(address)
        retaddr=address[start:end]
        retaddr=retaddr.strip()
        return retaddr


