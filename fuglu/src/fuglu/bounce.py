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
# $Id: bounce.py 7 2009-04-09 06:51:25Z oli $
#

import smtplib
from string import Template
import traceback
import logging
import os
import unittest


class Bounce:
    """Send Mail (Bounces)"""
    
    def __init__(self,config):
        self.logger=logging.getLogger('fuglu.bouncer')
        self.config=config
    
    
    
    def apply_template(self,templatecontent,suspect,values):
        values['from_address']=suspect.from_address
        values['to_address']=suspect.to_address
        values['subject']=suspect.getMessageRep()['subject']
        
        template = Template(templatecontent)
        
        message= template.safe_substitute(values)
        return message
        
    
    def send_raw_template(self,recipient,templatefile,suspect,values):
        """Send a E-Mail Bounce Message
        
        recipient     -- Message recipient (bla@bla.com)
        templatefile  -- Template to use
        suspect      -- suspect that caused the bounce
        values       -- Values to apply to the template
        
        If the suspect has the 'nobounce' tag set, the message will not be sent. The same happens
        if the global configuration 'disablebounces' is set.
        """
        if suspect.get_tag('nobounce'):
            self.logger.info('Not sending bounce to %s - bounces disabled by plugin'%recipient)
            return
        
        if not os.path.exists(templatefile):
            self.logger.error('Template file does not exist: %s'%templatefile)
            return
        
        fp=open(templatefile)
        filecontent=fp.read()
        fp.close()
        
        self.logger.debug('Sending bounce message to %s'%recipient)
        fromaddress="<>"
        
        message=self.apply_template(filecontent, suspect, values)

        self._send(fromaddress, recipient, message)
    
    def _send(self,fromaddress,toaddress,message):
        if self.config.get('main','disablebounces'):
            self.logger.warning('Bounces are disabled in config - not sending message to %s'%toaddress)
            return
        smtpServer = smtplib.SMTP('127.0.0.1',self.config.getint('main', 'outgoingport'))
        smtpServer.helo(self.config.get('main','outgoinghelo'))
        smtpServer.sendmail(fromaddress, recipient, message)
        smtpServer.quit()
        
        
class TemplateTestcase(unittest.TestCase):
    """Test Templates"""
    def setUp(self):     
        pass
 
    def tearDown(self):
        pass     

    def test_hf(self):
        """Test header filters"""
        from fuglu.shared import Suspect

        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org','testdata/helloworld.eml')
        suspect.tags['nobounce']=True
        
        reason="a three-headed monkey stole it"
        
        template="""Your message '${subject}' from ${from_address} to ${to_address} could not be delivered because ${reason}"""
        
        result=Bounce(None).apply_template(template, suspect, dict(reason=reason))
        expected="""Your message 'Hello world!' from sender@unittests.fuglu.org to recipient@unittests.fuglu.org could not be delivered because a three-headed monkey stole it"""
        self.assertEquals(result,expected),"Got unexpected template result: %s"%result
        
        
        