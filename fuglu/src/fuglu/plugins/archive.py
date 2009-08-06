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
        self.requiredvars=(('ArchivePlugin','archiverules'),('ArchivePlugin','archivedir'),('ArchivePlugin','makedomainsubdir'),('ArchivePlugin','storeoriginal'))
        self.headerfilter=None
    
    def lint(self):
        allok=(self.checkConfig() and self.lint_dirs())
        return allok
    
    def lint_dirs(self):
        archivedir=self.config.get('ArchivePlugin', 'archivedir')
        if archivedir=="":
            print 'Archivedir is not specified'
            return False
        
        if not os.path.isdir(archivedir):
            print "Archivedir '%s' does not exist or is not a directory"%(archivedir)
            return False
        
        return True
        
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
        if self.config.getboolean('ArchivePlugin','storeoriginal'):
            shutil.copy(suspect.tempfile, filename)
        else:
            fp=fopen(filename,'w')
            fp.write(suspect.getMessageRep().as_string())
            fp.close()
            
        self._logger().info('Message from %s to %s archived as %s'%(suspect.from_address,suspect.to_address,filename))
        return filename
        
        
    
    def __str__(self):
        return 'ArchivePlugin';
    

#### UNIT TESTS

class ArchiveTestcase(unittest.TestCase):
    """Tests that all plugins should pass"""
    def setUp(self):
        import ConfigParser
        import tempfile
        self.tempfiles=[]
        
        config=ConfigParser.RawConfigParser()
        config.add_section('main')
        config.set('main', 'disablebounces', '1')
        
        config.add_section('ArchivePlugin')
        config.set('ArchivePlugin', 'archivedir', '/tmp')
        config.set('ArchivePlugin', 'mkdomainsubdirs', 0)
        config.set('ArchivePlugin', 'storeoriginal', 1)
        
        tempfilename=tempfile.mktemp(suffix='archive', prefix='fuglu-unittest', dir='/tmp')
        fp=open(tempfilename,'w')
        fp.write('From unittests.fuglu.org')
        self.tempfiles.append(tempfilename)
        config.set('ArchivePlugin', 'archiverules', tempfilename)
        
        self.config=config
        
 
    def tearDown(self):
        for tempfile in self.tempfiles:
            os.remove(tempfile)       

    def test_output(self):
        from fuglu.shared import Suspect
        import shutil
        import tempfile
        origmessage=fopen('testdata/helloworld.eml').read()
        tempfilename=tempfile.mktemp(suffix='archive', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy('testdata/helloworld.eml',tempfilename)
        self.tempfiles.append(tempfilename)
        
        candidate=ArchivePlugin(self.config)
        suspect=Suspect('sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tempfilename)
        
        filename=candidate.archive(suspect)
        self.assertTrue(filename!=None and filename)
        
        
        
        
        