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

import smtplib
import traceback
import logging
import os
import unittest

from fuglu.shared import apply_template

class Bounce:
    """Send Mail (Bounces)"""
    
    def __init__(self,config):
        self.logger=logging.getLogger('fuglu.bouncer')
        self.config=config
        
    
    def send_template_file(self,recipient,templatefile,suspect,values):
        """Send a E-Mail Bounce Message
        
        recipient     -- Message recipient (bla@bla.com)
        templatefile  -- Template to use
        suspect      -- suspect that caused the bounce
        values       -- Values to apply to the template
        
        If the suspect has the 'nobounce' tag set, the message will not be sent. The same happens
        if the global configuration 'disablebounces' is set.
        """
        
        if not os.path.exists(templatefile):
            self.logger.error('Template file does not exist: %s'%templatefile)
            return
        
        fp=open(templatefile)
        filecontent=fp.read()
        fp.close()
        self.send_template_string(recipient, filecontent, suspect, values)
        
    
    def send_template_string(self,recipient,templatecontent,suspect,values):
        """Send a E-Mail Bounce Message
        
        recipient     -- Message recipient (bla@bla.com)
        templatecontent  -- Template to use
        suspect      -- suspect that caused the bounce
        values       -- Values to apply to the template
        
        If the suspect has the 'nobounce' tag set, the message will not be sent. The same happens
        if the global configuration 'disablebounces' is set.
        """
        if suspect.get_tag('nobounce'):
            self.logger.info('Not sending bounce to %s - bounces disabled by plugin'%recipient)
            return
        
        message=apply_template(templatecontent, suspect, values)

        self.logger.debug('Sending bounce message to %s'%recipient)
        fromaddress="<>"
        self._send(fromaddress, recipient, message)
    
    def _send(self,fromaddress,toaddress,message):
        if self.config.getboolean('main','disablebounces'):
            self.logger.warning('Bounces are disabled in config - not sending message to %s'%toaddress)
            return
        smtpServer = smtplib.SMTP('127.0.0.1',self.config.getint('main', 'outgoingport'))
        helo=self.config.get('main','outgoinghelo')
        if helo.strip()=='':
            import socket
            helo=socket.gethostname()
        smtpServer.helo(helo)
        smtpServer.sendmail(fromaddress, toaddress, message)
        smtpServer.quit()