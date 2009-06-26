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
from mako.template import Template
from mako.exceptions import RichTraceback
import traceback
import logging
import os

class Bounce:
    """Send Mail (Bounces)"""
    
    def __init__(self,config):
        self.logger=logging.getLogger('fuglu.bouncer')
        self.config=config
    
    def send_raw_template(self,recipient,templatefile,suspect):
        """Send a E-Mail Bounce Message
        
        recipient     -- Message recipient (bla@bla.com)
        templatefile  -- Mako Template to use
        suspect       -- The suspect to retreive the values from 
        
        If the suspect has the 'nobounce' tag set, the message will not be sent. The same happens
        if the global configuration 'disablebounces' is set.
        """
        if suspect.get_tag('nobounce'):
            self.logger.info('Not sending bounce to %s - bounces disabled by plugin'%recipient)
            return
        
        if not os.path.exists(templatefile):
            self.logger.error('Template file does not exist: %s'%templatefile)
            return
        self.logger.debug('Sending bounce message to %s'%recipient)
        fromaddress="<>"

        template = Template(filename=templatefile)
        
        message=None
        try:
            message= template.render(suspect=suspect)
        except:
            traceback = RichTraceback()
            for (filename, lineno, function, line) in traceback.traceback:
                self.logger.error( "File %s, line %s, in %s" % (filename, lineno, function))
                self.logger.error( line, "\n")
            self.logger.error( "%s: %s" % (str(traceback.error.__class__.__name__), traceback.error))
        
        if message==None:
            return
        self._send(fromaddress, recipient, message)
    
    def _send(self,fromaddress,toaddress,message):
        if self.config.get('main','disablebounces'):
            self.logger.warning('Bounces are disabled in config - not sending message to %s'%toaddress)
            return
        smtpServer = smtplib.SMTP('127.0.0.1',self.config.getint('main', 'outgoingport'))
        smtpServer.helo(self.config.get('main','outgoinghelo'))
        smtpServer.sendmail(fromaddress, recipient, message)
        smtpServer.quit()