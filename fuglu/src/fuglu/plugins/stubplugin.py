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
"""
Stub Plugin

Tutorial docs go here...

"""

from fuglu.shared import ScannerPlugin,DUNNO
import time
import unittest



class StubPlugin(ScannerPlugin):
    """Copy this to make a new plugin"""
    def __init__(self,config):
        ScannerPlugin.__init__(self,config)
        
    def examine(self,suspect):
        #config Example
        #maxsize=self.config.getint('StubPlugin', 'maxsize')
        
        #debug example
        #self._logger().debug('hello world from StubPlugin')
          
        starttime=time.time()
        
        
        #PUT PLUGIN CODE HERE
        
        #For debugging, its good to know how long each plugin took
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['StubPlugin.time']="%.4f"%difftime
        return DUNNO
    
    def __str__(self):
        return 'StubPlugin';
    
    
class StubPluginTestCase(unittest.TestCase):
    """Testcases for the Stub Plugin"""
    def setUp(self):
        from ConfigParser import RawConfigParser        
        config=RawConfigParser()
        config.add_section('StubPlugin')
        config.set('StubPlugin', 'somekey','somevalue')
        self.candidate=StubPlugin(config)


    def test_something(self):
        """Test if examine runs through"""
        from fuglu.shared import Suspect
        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org','/dev/null')
        self.candidate.examine(suspect)
        self.failIf(suspect.get_tag('StubPlugin.time')==None, "Examine didnt't run through")
        