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
from fuglu.shared import ScannerPlugin,DELETE,DUNNO,DEFER,HeaderFilter
import time
import unittest
import os
import shutil

class ArchivePlugin(ScannerPlugin):
    """Store mails to archive"""
    def __init__(self,config):
        ScannerPlugin.__init__(self,config)
        self.requiredvars=(('ArchivePlugin','archiverules'),('ArchivePlugin','archivedir'),('ArchivePlugin','makedomainsubdir'))
        self.headerfilter=None
        
        
    def examine(self,suspect):
        starttime=time.time()
        
        archiverules=self.config.get('ArchivePlugin', 'archiverules')
        if archiverules==None or archiverules=="":
            return DUNNO
        
        if not os.path.exists(archiverules):
            self._logger().error('Archive Rules file does not exist : %s'%archiverules)
            return DUNNO
        
        if self.headerfilter==None:
            self.headerfilter=HeaderFilter(archiverules)
        
        (match,arg)=self.headerfilter.matches(suspect)
        if match:
            self.archive(suspect)
        
        #For debugging, its good to know how long each plugin took
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['ArchivePlugin.time']="%.4f"%difftime
    
    def archive(self,suspect):
        archivedir=self.config.get('ArchivePlugin', 'archivedir')
        if archivedir=="":
            self._logger().error('Archivedir is not specified')
            return
        
        finaldir=archivedir
        
        makedomainsubdir=self.config.getboolean('ArchivePlugin','makedomainsubdir')
        if makedomainsubdir:
            finaldir="%s/%s"%(archivedir,suspect.to_domain)
        
        if not os.path.isdir(finaldir):
            os.makedirs(finaldir,0755)
        
        filename="%s/%s"%(finaldir,suspect.id)
        
        shutil.copy(suspect.tempfile, filename)
        self._logger().info('Message from %s to %s archived as %s'%(suspect.from_address,suspect.to_address,filename))
        
        
    
    def __str__(self):
        return 'ArchivePlugin';
    

        