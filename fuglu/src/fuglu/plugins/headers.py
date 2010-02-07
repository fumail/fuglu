"""
Headerplugin
"""

from fuglu.shared import ScannerPlugin,DELETE,DUNNO,DEFER
import time
import unittest



class HeaderPlugin(ScannerPlugin):
    """Removes existing Headers"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars=((self.section, 'removeheaders'),)
        
    def examine(self,suspect):
        removeheaders=self.config.get(self.section, 'removeheaders').split(',')
        
        #debug example
        #self._logger().debug('hello world from StubPlugin')
          
        starttime=time.time()
        
        msgrep=suspect.getMessageRep()
        for header in removeheaders:
            if msgrep.has_key(msgrep):
                self ._logger().debug('Removed Header: %s'%header)
                del msgrep[header]
        
        #For debugging, its good to know how long each plugin took
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['HeaderPlugin.time']="%.4f"%difftime
    
    def __str__(self):
        return 'HeaderPlugin';
    
    
class HeaderPluginTestCase(unittest.TestCase):
    """Testcases for the Stub Plugin"""
    def setUp(self):
        from ConfigParser import RawConfigParser        
        config=RawConfigParser()
        config.add_section('HeaderPlugin')
        config.set('HeaderPlugin', 'removeheaders','X-Doenertier')
        self.candidate=HeaderPlugin(config)


        