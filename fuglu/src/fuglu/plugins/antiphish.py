"""
Antiphish / Forging Plugins (DKIM / SPF / SRS etc)

EXPERIMENTAL, not ready for production!
"""

from fuglu.shared import ScannerPlugin,apply_template,DUNNO,string_to_actioncode
import time
import unittest
import os


class DKIMVerify(ScannerPlugin):
    """DKIM Verify plugin - EXPERIMENTAL!"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars={
                'invalidsigaction':{
                 'description':"Action when dkim sig failed",
                 'default':"DUNNO",                  
                },
                'rejectmessage':{
                 'description':"If invalidsigaction=REJECT, return this message as reject template",
                 'default':"DKIM verification failed",                  
                },
                'fugluspamlevel':{
                  'description':"if dkim sig fails, treat message in fuglu as... lowspam / highspam / (empty)",
                  'default':'',           
                },
                           
                'maxsize':{
                'default':'256000',
                'description':"maximum size in bytes. larger messages will be skipped",
                },
        }
        self.logger=self._logger()

    def __str__(self):
        return "DKIM Verify"    
    
    def examine(self,suspect):  
        
        spamsize=suspect.size
        maxsize=self.config.getint(self.section, 'maxsize')
        if spamsize>maxsize:
            suspect.debug('Too big for dkim check. %s > %s'%(spamsize,maxsize))
            suspect.set_tag('DKIMVerify.skipreason','size skip')
            return DUNNO
        
        starttime=time.time()

        source=suspect.getSource()
        if "dkim-signature: " not in suspect.get_headers().lower():
            suspect.debug("No dkim signature header found")
            return DUNNO
        
        import sys
        suspect.set_tag('debugfile',sys.stdout)
        
        from fuglu.lib.patcheddkimlib import verify
        valid=verify(source,suspect.get_tag('debugfile'))
        suspect.set_tag("DKIMVerify.sigvalid",valid)
        
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['DKIMVerify.time']="%.4f"%difftime
        
        level=self.config.get(self.section,'fugluspamlevel')
        if level!=None and level.strip()!='':
            level=level.lower().strip()
            if level=='lowspam' or level=='highspam':
                suspect.tags['lowspam']['DKIM']=not valid
                suspect.tags['highspam']['DKIM']=False
            if level=='highspam':
                suspect.tags['highspam']['DKIM']=not valid
        
        if not valid:
            action=self.config.get(self.section,'invalidsigaction')
            actioncode=string_to_actioncode(action,self.config)
            message=apply_template(self.config.get(self.section,'rejectmessage'), suspect)
            return actioncode,message
    
        return DUNNO 

class DKIMSign(ScannerPlugin):
    """Add DKIM Signature"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars={
                'privatekeyfile':{
                 'description':"Location of the private key file. supports template variables like ${from_domain}",
                 'default':"/etc/fuglu/dkim/${from_domain}.key",                  
                },
                           
                'canonicalizeheaders':{
                 'description':"Type of header canonicalization (simple or relaxed)",
                 'default':"simple",                  
                },
                           
                'canonicalizebody':{
                 'description':"Type of body canonicalization (simple or relaxed)",
                 'default':"relaxed",                  
                },
                           
                'selector':{
                 'description':'selector to use when signing, supports templates',
                 'default':'default',
                },
                           
                'signheaders':{
                 'description':'comma separated list of headers to sign. empty string=sign all headers',
                 'default':'',
                },
                           
                'signbodylength':{
                  'description':'include l= tag in dkim header',
                  'default':'False',                
                },
        }

    def __str__(self):
        return "DKIM Sign"
    
    def examine(self,suspect):
        starttime=time.time()
        message=suspect.getSource()
        from fuglu.lib.patcheddkimlib import sign,Simple,Relaxed
        
        
        selector=apply_template(self.config.get(self.section,'selector'),suspect)
        domain=suspect.from_domain
        privkeyfile=apply_template(self.config.get(self.section,'privatekeyfile'), suspect)
        if not os.path.isfile(privkeyfile):
            self._logger().error("DKIM Sign failed for domain %s, private key not found: %s"%(domain,privkeyfile))
            return DUNNO
        privkeycontent=open(privkeyfile,'r').read()
        
        
        canH=Simple
        canB=Simple
        
        if self.config.get(self.section,'canonicalizeheaders').lower()=='relaxed':
            canH=Relaxed
        if self.config.get(self.section,'canonicalizebody').lower()=='relaxed':
            canB=Relaxed    
        canon=(canH,canB)
        headerconfig=self.config.get(self.section,'signheaders')
        if headerconfig==None or headerconfig.strip()=='':
            inc_headers=None
        else:
            inc_headers=headerconfig.strip().split(',')
        
        blength=self.config.getboolean(self.section,'signbodylength')
        
        dkimhdr=sign(message, selector, domain, privkeycontent, canonicalize=canon, include_headers=inc_headers, length=blength, debuglog=suspect.get_tag('debugfile'))
        if dkimhdr.startswith('DKIM-Signature: '):
            dkimhdr=dkimhdr[16:]
        
        suspect.addheader('DKIM-Signature',dkimhdr,immediate=True)
        
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['DKIMSign.time']="%.4f"%difftime
        
class SPFCheck(ScannerPlugin):
    """Check SPF"""
    
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars={        
        }
    
    
    def __str__(self):
        return "SPF"

    def examine(self,suspect):
        starttime=time.time()
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['SPFCheck.time']="%.4f"%difftime
        
    
class SRSRewrite(ScannerPlugin):
    """SRS Rewrites - would only work in after queue mode"""
    
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars={        
        }
    
    def __str__(self):
        return "SRS"

    def examine(self,suspect):
        starttime=time.time()
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['SPFCheck.time']="%.4f"%difftime
        

#TODO: unit tests   