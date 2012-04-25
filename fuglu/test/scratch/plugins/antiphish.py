"""
DKIM Sign / Verify Plugin
"""

from fuglu.shared import ScannerPlugin
import time
import unittest

#rename this file to phising or something?



class DkimVerify(ScannerPlugin):
    """DKIM Verify plugin - just a test, far from working"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars=()
    
    
    def lint(self):
        allok=(self.checkConfig() and self.lint_dkimimport())
        return allok
    
    def lint_dkimimport(self):
        try:
            import dkim
        except ImportError:
            print "python pydkim library not installed. "
            return False
        return True
      
    def examine(self,suspect):  
        starttime=time.time()
        
        source=suspect.getSource()
        
        import dkim        
        valid=dkim.verify(source,suspect.get_tag('debugfile'))
        suspect.debug( "DKIM Source Valid: %s"%valid)
        
        #For debugging, its good to know how long each plugin took
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['HeaderPlugin.time']="%.4f"%difftime
    

class DKIMSign(ScannerPlugin):
    """Removes existing Headers"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars=()
    
    
    def lint(self):
        allok=(self.checkConfig() and self.lint_dkimimport() and self.lint_privatekey())
        return allok
    
    def lint_dkimimport(self):
        try:
            import dkim
        except ImportError:
            print "python pydkim library not installed. "
            return False
        return True
      
    def lint_privatekey(self):
        return True
        