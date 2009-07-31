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
from fuglu.shared import ScannerPlugin,DELETE,DUNNO,DEFER,Suspect
import time
from socket import *
import email
import re
import unittest

class SAPlugin(ScannerPlugin):
    """Spamassassin Plugin"""
    def __init__(self,config):
        ScannerPlugin.__init__(self,config)
        self.requiredvars=(('SAPlugin','peruserconfig'),('SAPlugin','host'),('SAPlugin','port'),('SAPlugin','maxsize'),('SAPlugin','spamheader'),('SAPlugin','timeout'),('SAPlugin','retries'))

    def lint(self):
        allok=(self.checkConfig() and self.lint_ping() and self.lint_spam())
        return allok

    def lint_ping(self):
        """ping sa"""
        serverHost = self.config.get('SAPlugin','host')          
        serverPort = self.config.getint('SAPlugin','port')
        timeout=self.config.getint('SAPlugin','timeout')
        retries = self.config.getint('SAPlugin','retries')
        for i in range(0,retries):
            try:
                self._logger().debug('Contacting spamd %s (Try %s of %s)'%(serverHost,i+1,retries))
                s = socket(AF_INET, SOCK_STREAM)   
        
                s.settimeout(timeout)
                s.connect((serverHost, serverPort)) 
                s.sendall('PING SPAMC/1.2')
                s.sendall("\r\n")
                s.shutdown(1)
                socketfile=s.makefile("rb")
                line=socketfile.readline()
                answer=line.strip().split()
                if len(answer)!=3:
                    print "Invalid SPAMD PONG: %s"%line
                    return False
                
                if answer[2]!="PONG":
                    print "Invalid SPAMD Pong: %s"%line
                    return False
                print "Got: %s"%line
                return True
            except timeout:
                print('SPAMD Socket timed out.')
            except herror,h:
                print('SPAMD Herror encountered : %s'%str(h))
            except gaierror,g:
                print('SPAMD gaierror encountered: %s'%str(g))
            except error,e:
                print('SPAMD socket error: %s'%str(e))
            
            time.sleep(1)
        return False
    
    
    def lint_spam(self):
        stream="""Date: Mon, 08 Sep 2008 17:33:54 +0200
To: oli@unittests.fuglu.org
From: oli@unittests.fuglu.org
Subject: test scanner

  XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
"""
        result=self.safilter(stream, 'test')
        if result.find('GTUBE ')>-1:
            print "GTUBE Has been detected correctly"
            return True
        else:
            print "SA did not detect GTUBE"
            return False
        
    def examine(self,suspect):
        #check if someone wants to skip sa checks
        if suspect.get_tag('SAPlugin.skip')==True:
            self._logger().debug('Skipping SA Plugin (requested by previous plugin)')
            return
        
        spamsize=suspect.size
        suspect.debug('Message size: %s'%spamsize)
        
        maxsize=self.config.getint('SAPlugin', 'maxsize')
        spamheadername=self.config.get('SAPlugin','spamheader')
        
        if spamsize>maxsize:
            self._logger().info('Size Skip, %s > %s'%(spamsize,maxsize))
            suspect.debug('Too big for spamchecks. %s > %s'%(spamsize,maxsize))
            return
        
        starttime=time.time()
        
        spam=suspect.getMessageRep().as_string()
        
        filtered=self.safilter(spam,suspect.to_address)
        content=None
        if filtered==None:
            suspect.debug('SA Scan failed - please check error log')
            self._logger().error('SA scan FAILED. Deferring message')
            return DEFER
            
            #this would acceppt the message
            #suspect.addheader('%sSA-SKIP'%self.config.get('main','prependaddedheaders'),'SA scan failed')
            #content=spam
            
        else:
            content=filtered 
        
        newmsgrep=email.message_from_string(content)
        
        suspect.setMessageRep(newmsgrep)

        isspam=False
        spamheader=newmsgrep[spamheadername]
        
        spamscore=None
        if spamheader==None:
            self._logger().warning('Did not find Header %s in returned message from SA'%spamheadername)
        else:
            if len(spamheader)>2 and spamheader.lower()[0:3]=='yes':
                isspam=True
            patt=re.compile('Score=([\-\d\.]+)',re.IGNORECASE)
            m=patt.search(spamheader)
            
            if m !=None:
                spamscore=float(m.group(1))
                self._logger().debug('Spamscore: %s'%spamscore)
                suspect.debug('Spamscore: %s'%spamscore)
            else:
                self._logger().warning('Could not extract spam score from header: %s'%spamheader)
                suspect.debug('Could not read spam score from header %s'%spamheader)
         
        
        if isspam:
            self._logger().debug('Message is spam')
            suspect.debug('Message is spam')
        else:
            self._logger().debug('Message is not spam')
            suspect.debug('Message is not spam')   
        
        
        
            
        suspect.tags['spam']['SpamAssassin']=isspam
        if spamscore != None:
            suspect.tags['SAPlugin.spamscore']=spamscore
 
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['SAPlugin.time']="%.4f"%difftime
        return DUNNO
        
    def safilter(self,messagecontent,user):
        """pass content to sa, return cleaned mail"""
        serverHost = self.config.get('SAPlugin','host')          
        serverPort = self.config.getint('SAPlugin','port')
        timeout=self.config.getint('SAPlugin','timeout')
        retries = self.config.getint('SAPlugin','retries')
        peruserconfig = self.config.getboolean('SAPlugin','peruserconfig')
        spamsize=len(messagecontent)
        for i in range(0,retries):
            try:
                self._logger().debug('Contacting spamd %s (Try %s of %s)'%(serverHost,i+1,retries))
                s = socket(AF_INET, SOCK_STREAM)   
        
                s.settimeout(timeout)
                s.connect((serverHost, serverPort)) 
                s.sendall('PROCESS SPAMC/1.2')
                s.sendall("\r\n")
                s.sendall("Content-length: %s"%spamsize)
                s.sendall("\r\n")
                if peruserconfig:
                    s.sendall("User: %s"%user)
                    s.sendall("\r\n")
                s.sendall("\r\n")
                s.sendall(messagecontent)
                self._logger().debug('Sent %s bytes to spamd'%spamsize)
                s.shutdown(1)
                socketfile=s.makefile("rb")
                line1_info=socketfile.readline()
                self._logger().debug(line1_info)
                line2_contentlength=socketfile.readline()
                line3_empty=socketfile.readline()
                content=socketfile.read()
                self._logger().debug('Got %s message bytes from back from spamd'%len(content))
                answer=line1_info.strip().split()
                if len(answer)!=3:
                    self._logger().error("Got invalid status line from spamd: %s"%line1_info)
                    continue
                
                (version,number,status)=answer
                if status!='EX_OK':
                    self._logger().error("Got bad status from spamd: %s"%status)
                    continue
                
                return content
            except timeout:
                self._logger().error('SPAMD Socket timed out.')
            except herror,h:
                self._logger().error('SPAMD Herror encountered : %s'%str(h))
            except gaierror,g:
                self._logger().error('SPAMD gaierror encountered: %s'%str(g))
            except error,e:
                self._logger().error('SPAMD socket error: %s'%str(e))
            
            time.sleep(1)
        return None
                
    def __str__(self):
        return 'SAPlugin';
    
class SAPluginTestCase(unittest.TestCase):
    """Testcases for the Stub Plugin"""
    def setUp(self):
        from ConfigParser import RawConfigParser        
        config=RawConfigParser()
        config.add_section('SAPlugin')
        config.set('SAPlugin', 'host','127.0.0.1')
        config.set('SAPlugin', 'port','783')
        config.set('SAPlugin', 'timeout','5')
        config.set('SAPlugin', 'retries','3')
        config.set('SAPlugin', 'peruserconfig','0')
        config.set('SAPlugin', 'maxsize','500000')
        config.set('SAPlugin', 'spamheader','X-Spam-Status')
        self.candidate=SAPlugin(config)

    def test_score(self):
        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org','/dev/null')
        stream="""Date: Mon, 08 Sep 2008 17:33:54 +0200
To: oli@unittests.fuglu.org
From: oli@unittests.fuglu.org
Subject: test scanner

  XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
"""
        suspect.setMessageRep(email.message_from_string(stream))
        self.candidate.examine(suspect)
        score=int( suspect.get_tag('SAPlugin.spamscore'))
        self.failUnless(score>1000, "GTUBE mails should score > 1000")