"""
Antiphish / Forging Plugins (DKIM / SPF / SRS etc)

EXPERIMENTAL, not ready for production!

requires: dkimpy (not pydkim!!)

"""

from fuglu.shared import ScannerPlugin,apply_template,DUNNO,string_to_actioncode
import time
import unittest
import os
import pkg_resources
import re

DKIMPY_AVAILABLE=False
try:
    pkg_resources.get_distribution("dkimpy")
    from dkim import DKIM,sign,Simple,Relaxed,DKIMException
    
    ANY_DNSLIB_AVAILABLE=False
    try:
        import dns
        ANY_DNSLIB_AVAILABLE=True
    except ImportError:
        pass
    
    try:
        import DNS
        ANY_DNSLIB_AVAILABLE=True
    except ImportError:
        pass
    
    if not ANY_DNSLIB_AVAILABLE:
        raise Exception("no supported dns library available")
    
    DKIMPY_AVAILABLE=True
except:
    pass
    

class DKIMVerifyPlugin(ScannerPlugin):
    """**EXPERIMENTAL**
This plugin checks the DKIM signature of the message and sets tags...
DKIMVerify.sigvalid : True if there was a valid DKIM signature, False if there was an invalid DKIM signature
the tag is not set if there was no dkim header at all
    
DKIMVerify.skipreason: set if the verification has been skipped
    """
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars={

        }
        self.logger=self._logger()

    def __str__(self):
        return "DKIM Verify"    
    
    def examine(self,suspect):  
        if not DKIMPY_AVAILABLE:
            suspect.debug("dkimpy not available, can not check")
            suspect.set_tag('DKIMVerify.skipreason','dkimpy library not available')
            return DUNNO

        starttime=time.time()

        source=suspect.get_original_source()
        if "dkim-signature: " not in suspect.get_headers().lower():
            suspect.set_tag('DKIMVerify.skipreason','not dkim signed')
            suspect.debug("No dkim signature header found")
            return DUNNO
        d = DKIM(source,logger=suspect.get_tag('debugfile'))
        try:
            valid=d.verify(source)
        except DKIMException, de:
            self.logger.warning("%s: DKIM validation failed: %s"%(str(de)))
            valid=False
         
        suspect.set_tag("DKIMVerify.sigvalid",valid)
        
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['DKIMVerify.time']="%.4f"%difftime
        return DUNNO
    
    def lint(self):
        if not DKIMPY_AVAILABLE:
            print "Missing dependency: dkimpy https://launchpad.net/dkimpy"
            print "(also requires either dnspython or pydns)"
            return False
        
        return self.checkConfig()

class DKIMSignPlugin(ScannerPlugin):
    """**EXPERIMENTAL**
Add DKIM Signature to outgoing mails
    
Setting up your keys:

::

    mkdir -p /etc/fuglu/dkim
    openssl genrsa -out /etc/fuglu/dkim/example.com.key 1024
    openssl rsa -in /etc/fuglu/dkim/example.com.key -out /etc/fuglu/dkim/example.com.pub -pubout -outform PEM
    
If fuglu handles both incoming and outgoing mails you should make sure that this plugin is skipped for incoming mails
    """
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars={
                'privatekeyfile':{
                 'description':"Location of the private key file. supports standard template variables plus additional ${header_from_domain} which extracts the domain name from the From: -Header",
                 'default':"/etc/fuglu/dkim/${header_from_domain}.key",                  
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
    
    
    def get_header_from_domain(self,suspect):
        """extract the header from domain. Returns None if extraction fails or if there are multiple from headers"""
        msgrep=suspect.get_message_rep()
        from_headers=msgrep.get_all("From")
        if len(from_headers)!=1:
            return None
        
        from_header=from_headers[0]
        domain_match=re.search("(?<=@)[\w.-]+", from_header)
        if domain_match==None:
            return None
        domain=domain_match.group()
        return domain
        
    
    def examine(self,suspect):
        if not DKIMPY_AVAILABLE:
            suspect.debug("dkimpy not available, can not check")
            suspect.set_tag('DKIMVerify.skipreason','dkimpy library not available')
            return DUNNO
        
        starttime=time.time()
        message=suspect.get_source()
        domain=self.get_header_from_domain(suspect)
        addvalues=dict(header_from_domain=domain)
        selector=apply_template(self.config.get(self.section,'selector'),suspect,addvalues)
        
        if domain==None:
            self._logger().error("%s: Failed to extract From-header domain for DKIM signing"%suspect.id)
            return DUNNO
        
        privkeyfile=apply_template(self.config.get(self.section,'privatekeyfile'), suspect,addvalues)
        if not os.path.isfile(privkeyfile):
            self._logger().error("%s: DKIM signing failed for domain %s, private key not found: %s"%(suspect.id,domain,privkeyfile))
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
        
        dkimhdr=sign(message, selector, domain, privkeycontent, canonicalize=canon, include_headers=inc_headers, length=blength, logger=suspect.get_tag('debugfile'))
        if dkimhdr.startswith('DKIM-Signature: '):
            dkimhdr=dkimhdr[16:]
        
        suspect.addheader('DKIM-Signature',dkimhdr,immediate=True)
        
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['DKIMSign.time']="%.4f"%difftime

    def lint(self):
        if not DKIMPY_AVAILABLE:
            print "Missing dependency: dkimpy https://launchpad.net/dkimpy"
            print "(also requires either dnspython or pydns)"
            return False
        
        #if privkey is a filename (no placeholders) check if it exists
        privkeytemplate=self.config.get(self.section,'privatekeyfile')
        if '{' not in privkeytemplate and not os.path.exists(privkeytemplate):
            print "Private key file %s not found"%privkeytemplate
            return False
        
        return self.checkConfig()


# class SPFCheck(ScannerPlugin):
#     """Check SPF, RFC 4408 implementation"""
#     
#     SPF_NONE="None"
#     SPF_NEUTRAL="Neutral"
#     SPF_PASS="Pass"
#     SPF_FAIL="Fail"
#     SPF_SOFTFAIL="SoftFail"
#     SPF_TEMPERROR="TempError"
#     SPF_PERMERROR="PermError"
#     
#     
#     def __init__(self,config,section=None):
#         ScannerPlugin.__init__(self,config,section)
#         self.requiredvars={        
#         }
#     
#     
#     def __str__(self):
#         return "SPF"
# 
#     def examine(self,suspect):
#         starttime=time.time()
#         endtime=time.time()
#         difftime=endtime-starttime
#         suspect.tags['SPFCheck.time']="%.4f"%difftime
#         
# 
#     def check_spf(self,suspect):
#         pass
#     
#     
#     def check_host(self,ip,domain,sender):
#         """check_host according to rfc4408 section 4"""
#         
#         #TODO:
#         """If the <domain> is malformed (label longer than 63 characters, zero-length label not at the end, etc.) or is not a fully qualified domain name, or if the DNS lookup returns "domain does not exist" (RCODE 3), check_host() immediately returns the result "None"."""
#         
#         #TODO:
#         """If the <sender> has no localpart, substitute the string "postmaster" for the localpart."""
#         
#         #TODO: get records
#         
#         
#         pass
#     
#     
# class SRSRewrite(ScannerPlugin):
#     """SRS Rewrites - would only work in after queue mode"""
#     
#     def __init__(self,config,section=None):
#         ScannerPlugin.__init__(self,config,section)
#         self.requiredvars={        
#         }
#     
#     def __str__(self):
#         return "SRS"
# 
#     def examine(self,suspect):
#         starttime=time.time()
#         endtime=time.time()
#         difftime=endtime-starttime
#         suspect.tags['SPFCheck.time']="%.4f"%difftime
#         
# 
# 
# class DMARC(ScannerPlugin):
#     """Check DMARC and make sure either SPF or DKIM pass ok"""
    
#TODO: unit tests   