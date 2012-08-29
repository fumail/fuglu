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
# $Id$
#
from fuglu.shared import ScannerPlugin,string_to_actioncode,DEFER,DUNNO,actioncode_to_string,\
    DELETE, Suspect, apply_template
import socket
import string
import time
import unittest
import os


class ClamavPlugin(ScannerPlugin):
    """This plugin passes suspects to a clam daemon. 

Actions: This plugin will delete infected messages. If clamd is not reachable or times out, messages can be DEFERRED.

Prerequisites: You must have clamd installed (for performance reasons I recommend it to be on the same box, but this is not absoluely necessary)

Notes for developers:


Tags:
 
 * sets ``virus['ClamAV']`` (boolean)
 * sets ``ClamavPlugin.virus`` (list of strings) - virus names found in message
 * sets ``ClamavPlugin.time`` (float)
"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars={
            'host':{
                'default':'localhost',
                'description':'hostname where clamd runs',
            },
            
            'port':{
                'default':'3310',
                'description':"tcp port number or path to clamd.sock for unix domain sockets\nexample /var/lib/clamav/clamd.sock or on ubuntu: /var/run/clamav/clamd.ctl ",
            },
                         
            'timeout':{
                'default':'10',
                'description':'socket timeout',
            },
                           
            'maxsize':{
                'default':'22000000',
                'description':"maximum message size, larger messages will not be scanned.  \nshould match the 'StreamMaxLength' config option in clamd.conf ",
            },
                           
            'retries':{
                'default':'3',
                'description':'how often should fuglu retry the connection before giving up',
            },
                           
            'virusaction':{
                'default':'DEFAULTVIRUSACTION',
                'description':"action if infection is detected (DUNNO, REJECT, DELETE)",
            },
                           
            'problemaction':{
                'default':'DEFER',
                'description':"action if there is a problem (DUNNO, DEFER)",
            },
            
            'rejectmessage':{
                'default':'threat detected: ${virusname}',
                'description':"reject message template if running in pre-queue mode and virusaction=REJECT",
            },
        }        
        self.logger=self._logger()
    
    def __str__(self):
        return "Clam AV"
    
    def _problemcode(self):
        retcode=string_to_actioncode(self.config.get(self.section,'problemaction'), self.config)
        if retcode!=None:
            return retcode
        else:
            #in case of invalid problem action
            return DEFER
        
    def examine(self,suspect):
        starttime=time.time()
        
        if suspect.size>self.config.getint(self.section,'maxsize'):
            self.logger.info('Not scanning - message too big')
            return
        
        content=suspect.getSource()

        for i in range(0,self.config.getint(self.section,'retries')):
            try:
                viruses=self.scan_stream(content)
                if viruses!=None:
                    self.logger.info( "Virus found in message from %s : %s"%(suspect.from_address,viruses))
                    suspect.tags['virus']['ClamAV']=True
                    suspect.tags['ClamavPlugin.virus']=viruses
                    suspect.debug('viruses found in message : %s'%viruses)
                else:
                    suspect.tags['virus']['ClamAV']=False
                
                endtime=time.time()
                difftime=endtime-starttime
                suspect.tags['ClamavPlugin.time']="%.4f"%difftime
                
                if viruses!=None:
                    virusaction=self.config.get(self.section,'virusaction')
                    actioncode=string_to_actioncode(virusaction,self.config)
                    firstinfected,firstvirusname=viruses.items()[0]
                    values=dict(infectedfile=firstinfected,virusname=firstvirusname)
                    message=apply_template(self.config.get(self.section,'rejectmessage'), suspect, values)
                    return actioncode,message
                return DUNNO
            except Exception,e:
                self.logger.warning("Error encountered while contacting clamd (try %s of %s): %s"%(i+1,self.config.getint(self.section,'retries'),str(e)))
        self.logger.error("Clamdscan failed after %s retries"%self.config.getint(self.section,'retries'))
        content=None
        return self._problemcode()
  
    def scan_stream(self,buffer):
        """
        Scan a buffer
    
        buffer (string) : buffer to scan
    
        return either :
          - (dict) : {filename1: "virusname"}
          - None if no virus found
    
        May raise :
          - BufferTooLong : if the buffer size exceeds clamd limits
          - ScanError : in case of communication problem
        """
    
        s = self.__init_socket__()
    
        s.send('STREAM')
        port = int(s.recv(200).strip().split(' ')[1])
        self.logger.debug('Sending stream to clamd on host %s port %s'%(self.config.get(self.section,'host'),port))
        n=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        n.connect((self.config.get(self.section,'host'), port))
        sent = n.sendall(buffer)
        n.close()

        result='...'
        dr={}
        while result!='':
            result = s.recv(20000)
            if len(result)>0:
                filenm = result.strip().split(':')[0]
                virusname = result.strip().split(':')[1].strip()
                if virusname[-5:]=='ERROR':
                    raise Exception, virusname
                elif virusname!='OK':
                    dr[filenm]=virusname.replace(" FOUND",'')
        s.close()
        if dr=={}:
            return None
        else:
            return dr
        
    def __init_socket__(self):
        clamd_HOST=self.config.get(self.section,'host')
        unixsocket=False
        
        try:
            iport=int(self.config.get(self.section,'port'))
        except ValueError:
            unixsocket=True
        
        if unixsocket:
            sock=self.config.get(self.section,'port')
            if not os.path.exists(sock):
                raise Exception("unix socket %s not found"%sock)
            s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.config.getint(self.section,'timeout'))
            try:
                s.connect(sock)
            except socket.error:
                raise Exception('Could not reach clamd using unix socket %s' % sock)
        else:
            clamd_PORT=int(self.config.get(self.section,'port'))
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.config.getint(self.section,'timeout'))
            try:
                s.connect((clamd_HOST, clamd_PORT))
            except socket.error:
                raise Exception('Could not reach clamd using network (%s, %s)' % (clamd_HOST, clamd_PORT))
        
        return s
    
    def lint(self):
        viract=self.config.get(self.section,'virusaction')
        print "Virusaction: %s"%actioncode_to_string(string_to_actioncode(viract,self.config))
        allok=(self.checkConfig() and self.lint_ping() and self.lint_eicar())
        return allok
    
    def lint_ping(self):
        try:
            s = self.__init_socket__()
        except Exception,e:
            print "Could not contact clamd: %s"%(str(e))
            return False
        s.send('PING')
        result = s.recv(20000)
        print "Got Pong: %s"%result
        if result.strip()!='PONG':
            print "Invalid PONG:"%result
        return True
    
    def lint_eicar(self):
        stream="""Date: Mon, 08 Sep 2008 17:33:54 +0200
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

        result=self.scan_stream(stream)
        if result==None:
            print "EICAR Test virus not found!"
            return False
        print "Clamav found virus",result
        return True
    
    
class ClamavPluginTestCase(unittest.TestCase):
    """Testcases for the Stub Plugin"""
    def setUp(self):
        from ConfigParser import RawConfigParser  
        import os      
        config=RawConfigParser()
        config.add_section('main')
        config.add_section('virus')
        config.set('main','prependaddedheaders','X-Fuglu-')
        config.set('virus','defaultvirusaction','DELETE')
        config.add_section('ClamavPlugin')
        config.set('ClamavPlugin', 'host','127.0.0.1')
        config.set('ClamavPlugin', 'port','3310')
        config.set('ClamavPlugin', 'timeout','5')
        config.set('ClamavPlugin', 'retries','3')
        config.set('ClamavPlugin', 'maxsize','22000000')
        config.set('ClamavPlugin', 'virusaction','DEFAULTVIRUSACTION')
        config.set('ClamavPlugin', 'problemaction','DEFER')
        config.set('ClamavPlugin', 'rejectmessage','')

        self.candidate=ClamavPlugin(config)

    def test_result(self):
        """Test if EICAR virus is detected and message deleted"""
        import email
        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org','/dev/null')
        stream="""Date: Mon, 08 Sep 2008 17:33:54 +0200
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

        suspect.setMessageRep(email.message_from_string(stream))
        result=self.candidate.examine(suspect)
        if type(result) is tuple:
            result,message=result
        strresult=actioncode_to_string(result)
        self.assertEqual(strresult,"DELETE")