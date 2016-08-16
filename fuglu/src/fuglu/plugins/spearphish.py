# -*- coding: utf-8 -*-

"""
# spearphish

The spearphish plugin checks if Header-From domain matches the envelope-to Domain ("Mail
from my own domain"), but has a different envelope sender domain. This blocks most of the
spear phish attempts as long as they don't start altering the domain names.
"""

import os
from fuglu.shared import ScannerPlugin,DUNNO,FileList,string_to_actioncode,apply_template
import string



class SpearPhishPlugin(ScannerPlugin):
    """Mark spear phishing mails as virus

    A message is assumed to be a spearphish if:
        - Header from domain = recipient domain
        - Envelope sender domain != header from domain

    """
    def __init__(self,section=None):
        ScannerPlugin.__init__(self,section)
        self.filelist=FileList(strip=True, skip_empty=True, skip_comments=True, lowercase=True, additional_filters=None, minimum_time_between_reloads=30)

        self.requiredvars={
            'domainsfile':{
                'default':'/etc/fuglu/spearphish-domains',
                'description':'Filename where we load spearphish domains from. One domain per line',
            },
            'virusenginename':{
                'default':'Fuglu SpearPhishing Protection',
                'description':'Name of this plugins av engine',
            },
            'virusname':{
                'default':'TRAIT.SPEARPHISH',
                'description':'Name to use as virus signature',
            },
            'virusaction': {
                'default': 'DEFAULTVIRUSACTION',
                'description': "action if spear phishing attempt is detected (DUNNO, REJECT, DELETE)",
            },
            'rejectmessage': {
                'default': 'threat detected: ${virusname}',
                'description': "reject message template if running in pre-queue mode and virusaction=REJECT",
            },
        }
        
        

    def examine(self,suspect):
        domainsfile = self.config.get(self.section,'domainsfile')
        if not os.path.exists(domainsfile):
            return DUNNO
            
        self.filelist.filename = domainsfile
        envelope_recipient_domain=suspect.to_domain.lower()
        checkdomains = self.filelist.get_list()
        if envelope_recipient_domain not in checkdomains:
            return DUNNO

        envelope_sender_domain=suspect.from_domain.lower()
        if envelope_sender_domain==envelope_recipient_domain:
            return DUNNO #we only check the message if the env_Sender_domain differs. If it's the same it will be caught by other means (like SPF)

        header_from_domain=self.extract_from_domain(suspect)
        if header_from_domain is None:
            self._logger().warn("%s: Could not extract header from domain for spearphish check"%suspect.id)
            return DUNNO

        if header_from_domain==envelope_recipient_domain:
            virusname = self.config.get(self.section, 'virusname')
            virusaction = self.config.get(self.section, 'virusaction')
            actioncode = string_to_actioncode(virusaction, self.config)
            
            logmsg = '%s: spear phish pattern detected, recipient=%s env_sender_domain=%s header_from_domain=%s'%(suspect.id,suspect.to_address,envelope_sender_domain,header_from_domain)
            self._logger().info(logmsg)
            self.flag_as_phish(suspect, virusname)
            
            message = apply_template(
                self.config.get(self.section, 'rejectmessage'), suspect, {'virusname':virusname})
            return actioncode, message
            
        return DUNNO



    def flag_as_phish(self,suspect, virusname):
        suspect.tags['%s.virus'%self.config.get(self.section,'virusenginename')]={'message content':virusname}
        suspect.tags['virus'][self.config.get(self.section,'virusenginename')]=True



    def extract_from_domain(self, suspect, headername='From'):
        """
        Try to extract domain of from header
        """
        try:
            msgrep=suspect.get_message_rep()
            address= msgrep.get(headername)
            if address is None:
                return None

            start = address.find('<') + 1
            if start < 1: # malformed header does not contain <> brackets
                start = address.find(':') + 1 # start >= 0

            if start >= 0:
                end = string.find(address, '>')
                if end < 0:
                    end = len(address)
            else:
                return None
                    
            retaddr = address[start:end]
            retaddr = retaddr.strip()

            if '@' not in retaddr:
                return None

            domain=retaddr.split('@',1)[-1]

            return domain.lower()
        except Exception:
            return None



    def __str__(self):
        return "Spearphish Check"



    def lint(self):
        allok=(self.checkConfig() and self.lint_file())
        return allok



    def lint_file(self):
        filename=self.config.get(self.section,'domainsfile')
        if not os.path.exists(filename):
            print("Spearphish domains file %s not found"%(filename))
            return False
        return True