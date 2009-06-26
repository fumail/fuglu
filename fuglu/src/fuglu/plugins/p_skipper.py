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
# $Id: p_skipper.py 9 2009-04-09 07:35:16Z oli $
#
from fuglu.shared import PrependerPlugin,HeaderFilter
import time
import os

class PluginSkipper(PrependerPlugin):
    """Skips plugins based on standard filter file"""
    def __init__(self,config):
        PrependerPlugin.__init__(self,config)
        self.filter=None
        self.requiredvars=(('PluginSkipper','filterfile'),)
        self.logger=self._logger()
        
    def pluginlist(self,suspect,pluginlist):
        """Removes scannerplugins based on headerfilter file"""
        if not self._initfilter():
            return None
        
        args=self.filter.getArgs(suspect)
        #each arg should be a comma separated list of classnames to skip
        
        skippluginlist=[]
        
        for arg in args:
            skippluginlist.extend(arg.split(','))
        
        
        listcopy=pluginlist[:]
        for plug in pluginlist:
            name=plug.__class__.__name__
            if name in skippluginlist:
                listcopy.remove(plug)
        return listcopy
    
    def _initfilter(self):
        if self.filter!=None:
            return True
        
        filename=self.config.get('PluginSkipper','filterfile')
        if filename==None or filename=="":
            return False
        
        if not os.path.exists(filename):
            self.logger.error('Filterfile not found for skipper: %s'%filename)
            return False
        
        
        self.filter=HeaderFilter(filename)
        return True
    
        
    def __str__(self):
        return 'PluginSkipper';