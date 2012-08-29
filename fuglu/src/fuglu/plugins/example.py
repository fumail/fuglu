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
#
"""
Example Plugin
"""

from fuglu.shared import ScannerPlugin,DUNNO
import time
import unittest



class ExamplePlugin(ScannerPlugin):
    """Copy this to make a new plugin"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars={
            'greeting':{
                'default':'hello world!',
                'description':'greeting the plugin should log to the console',
            }
        }
        #DO NOT call self.config.get .. here!
     
    def __str__(self):
        return "Example"
        
    def examine(self,suspect):
        #config Example
        greeting=self.config.get(self.section, 'greeting')
          
        starttime=time.time()
        
        
        #PUT PLUGIN CODE HERE
        #debug info in the plugin
        suspect.debug("Greeting: %s"%greeting)
        
        #log example
        self._logger().info("%s greets %s: %s"%(suspect.from_address,suspect.to_address,greeting))
        
        
        #For debugging, its good to know how long each plugin took
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['ExamplePlugin.time']="%.4f"%difftime
        return DUNNO
    
    
class ExamplePluginTestCase(unittest.TestCase):
    """Testcases for the Example Plugin"""
    def setUp(self):
        from ConfigParser import RawConfigParser        
        config=RawConfigParser()
        config.add_section('ExamplePlugin')
        config.set('ExamplePlugin', 'greeting','hi there!')
        self.candidate=ExamplePlugin(config)


    def test_something(self):
        """Test if examine runs through"""
        from fuglu.shared import Suspect
        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org','/dev/null')
        self.candidate.examine(suspect)
        self.failIf(suspect.get_tag('ExamplePlugin.time')==None, "Examine didn't run through")
        