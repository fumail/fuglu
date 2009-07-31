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
from fuglu.shared import PrependerPlugin,HeaderFilter
import time
import os

class MessageDebugger(PrependerPlugin):
    """Message Debugger Plugin"""
    def __init__(self,config):
        PrependerPlugin.__init__(self,config)
        self.filter=None
        self.logger=self._logger()
        
    def pluginlist(self,suspect,pluginlist):
        debugport=self.config.getint('debug','debugport')
        if suspect.get_tag('incomingport')==debugport:
            self.logger.info('Enabling debug mode for message on incoming port %s'%debugport)
            if self.config.getboolean('debug','nobounce'):
                suspect.tags['nobounce']=True
            if self.config.getboolean('debug','noreinject'):
                suspect.tags['noreinject']=True
            if self.config.getboolean('debug','noappender'):
                suspect.tags['noappender']=True
            fp=open(self.config.get('debug','debugfile'),'w')
            suspect.tags['debug']=True
            suspect.tags['debugfile']=fp
        self.logger.debug('Debugport: %s , Incoming port: %s'%(debugport,suspect.get_tag('incomingport')))
            

    def __str__(self):
        return 'MessageDebugger';