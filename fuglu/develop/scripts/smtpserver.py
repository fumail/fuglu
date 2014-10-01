#!/usr/bin/python
import sys
import os
import socket
import string
import tempfile

class SMTPServer:    
    def __init__(self,port=10029,address="127.0.0.1"):
        self.port=port
        self.stayalive=1
        
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((address, port))
            self._socket.listen(5)
        except Exception,e:
            print 'Could not start incoming SMTP Server: %s'%e
            sys.exit(1)
   
   
    def shutdown(self):
        self.stayalive=False
        self._socket.close()
        
    def serve(self):

        print 'SMTP Server running to port %s'%self.port
        while self.stayalive:
            try:
                nsd = self._socket.accept()
                if not self.stayalive:
                    break
                print 'Incoming connection from %s'%str(nsd[1])
                sess=SMTPSession(nsd[0])
                success=sess.getincomingmail()
                sess.endsession(250, "stored to /dev/null")
            except Exception,e:
                print 'Exception in serve(): %s'%str(e)

class SMTPSession:
    ST_INIT = 0
    ST_HELO = 1
    ST_MAIL = 2
    ST_RCPT = 3
    ST_DATA = 4
    ST_QUIT = 5
    
    def __init__(self, socket):
        self.from_address=None
        self.to_address=None
        self.helo=None
        
        self.socket = socket;
        self.state = SMTPSession.ST_INIT
        self.tempfile=None
        self.tempfilename=None

    def _send(self,content):
        print "> %s"%content.strip()
        self.socket.send(content)
        

    def endsession(self,code,message):
        self._send("%s %s\r\n"%(code,message))
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
                        self._send("%s %s\r\n"%(220,"BYE"))
                        self.closeconn()
                        return
                    self._send("%s %s\r\n"%(421,"Cannot accept further commands"))
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
        self._send("220 dummy server ready \r\n")
        while 1:
            data = ''
            completeLine = 0
            while not completeLine:
                lump = self.socket.recv(1024);
                if len(lump):
                    data += lump
                    if (len(data) >= 2) and data[-2:] == '\r\n':
                        completeLine = 1
                        print "< %s"%data
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
                                print'incoming message finished'
                                return True

                        self._send(rsp + "\r\n")
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
        if cmd == "HELO" or cmd=="EHLO":
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
            self.to_address=self.stripAddress(data)
        elif cmd == "DATA":
            if self.state != SMTPSession.ST_RCPT:
                return ("503 Bad command sequence", 1)
            self.state = SMTPSession.ST_DATA
            self.dataAccum = ""
            try:
                (handle,self.tempfilename)=tempfile.mkstemp()
                self.tempfile=os.fdopen(handle,'w+b')
                print "Created file %s"%self.tempfilename
            except:
                self.endsession(421, "could not create file %s"%self.tempfilename)

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
            if len(data)>5:
                self.tempfile.write(data[0:-6])
            self.tempfile.close()
            
            #todo: remove last 5 chars?
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

if len(sys.argv)>1:
 port=int(sys.argv[1])
 s=SMTPServer(port=port)
else:
 s=SMTPServer()
s.serve()
