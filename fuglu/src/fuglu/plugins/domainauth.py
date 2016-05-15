#   Copyright 2009-2016 Oli Schacher
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
"""
Antiphish / Forging Plugins (DKIM / SPF / SRS etc)

EXPERIMENTAL plugins

TODO: SRS

requires: dkimpy (not pydkim!!)
requires: pyspf
requires: pydns (or alternatively dnspython if only dkim is used) 
"""

from fuglu.shared import ScannerPlugin, apply_template, DUNNO, Suspect, FileList, string_to_actioncode
import time
import os
import pkg_resources
import re
import string

DKIMPY_AVAILABLE = False
PYSPF_AVAILABLE = False
PYDNS_AVAILABLE = False
DNSPYTHON_AVAILABLE = False
IPADDRESS_AVAILABLE = False
IPADDR_AVAILABLE = False

try:
    import dns
    DNSPYTHON_AVAILABLE = True
except ImportError:
    pass

try:
    import DNS
    PYDNS_AVAILABLE = True
except ImportError:
    pass

try:
    import ipaddress
    IPADDRESS_AVAILABLE = True
except:
    pass

try:
    import ipaddr
    IPADDR_AVAILABLE = True
except:
    pass

try:
    pkg_resources.get_distribution("dkimpy")
    from dkim import DKIM, sign, Simple, Relaxed, DKIMException

    if not (PYDNS_AVAILABLE or DNSPYTHON_AVAILABLE):
        raise Exception("no supported dns library available")

    DKIMPY_AVAILABLE = True
except:
    pass


try:
    if not PYDNS_AVAILABLE:
        raise Exception("pydns not available")
    if not (IPADDR_AVAILABLE or IPADDRESS_AVAILABLE):
        raise Exception("ipaddress/ipaddr not available")
    import spf
    PYSPF_AVAILABLE = True
except:
    pass


class DKIMVerifyPlugin(ScannerPlugin):

    """**EXPERIMENTAL**
This plugin checks the DKIM signature of the message and sets tags...
DKIMVerify.sigvalid : True if there was a valid DKIM signature, False if there was an invalid DKIM signature
the tag is not set if there was no dkim header at all

DKIMVerify.skipreason: set if the verification has been skipped

The plugin does not take any action based on the DKIM test result since a failed DKIM validation by itself
should not cause a message to be treated any differently. Other plugins might use the DKIM result
in combination with other factors to take action (for example a "DMARC" plugin could use this information)

It is currently recommended to leave both header and body canonicalization as 'relaxed'. Using 'simple' can cause the signature to fail.
    """

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {

        }
        self.logger = self._logger()

    def __str__(self):
        return "DKIM Verify"

    def examine(self, suspect):
        if not DKIMPY_AVAILABLE:
            suspect.debug("dkimpy not available, can not check")
            suspect.set_tag(
                'DKIMVerify.skipreason', 'dkimpy library not available')
            return DUNNO

        source = suspect.get_original_source()
        if "dkim-signature: " not in suspect.get_headers().lower():
            suspect.set_tag('DKIMVerify.skipreason', 'not dkim signed')
            suspect.debug("No dkim signature header found")
            return DUNNO
        d = DKIM(source, logger=suspect.get_tag('debugfile'))

        try:
            valid = d.verify()
        except DKIMException as de:
            self.logger.warning("%s: DKIM validation failed: %s" %
                                (suspect.id, str(de)))
            valid = False

        suspect.set_tag("DKIMVerify.sigvalid", valid)
        return DUNNO

    def lint(self):
        if not DKIMPY_AVAILABLE:
            print("Missing dependency: dkimpy https://launchpad.net/dkimpy")
            print("(also requires either dnspython or pydns)")
            return False

        return self.checkConfig()

# test:
# plugdummy.py -p ...  domainauth.DKIMSignPlugin -s <sender> -o canonicalizeheaders:relaxed -o canonicalizebody:simple -o signbodylength:False
# cat /tmp/fuglu_dummy_message_out.eml | swaks -f <sender>  -s <server>
# -au <username> -ap <password> -4 -p 587 -tls -d -  -t
# <someuser>@gmail.com


class DKIMSignPlugin(ScannerPlugin):

    """**EXPERIMENTAL**
Add DKIM Signature to outgoing mails

Setting up your keys:

::

    mkdir -p /etc/fuglu/dkim
    domain=example.com
    openssl genrsa -out /etc/fuglu/dkim/${domain}.key 1024
    openssl rsa -in /etc/fuglu/dkim/${domain}.key -out /etc/fuglu/dkim/${domain}.pub -pubout -outform PEM
    # print out the DNS record:
    echo -n "default._domainkey TXT  \\"v=DKIM1; k=rsa; p=" ; cat /etc/fuglu/dkim/${domain}.pub | grep -v 'PUBLIC KEY' | tr -d '\\n' ; echo ";\\""


If fuglu handles both incoming and outgoing mails you should make sure that this plugin is skipped for incoming mails


known issues:

 - setting canonicalizeheaders = simple will cause invalid signature.
 - signbodylength causes a crash in dkimlib "TypeError: sequence item 1: expected string, int found"

    """

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {
            'privatekeyfile': {
                'description': "Location of the private key file. supports standard template variables plus additional ${header_from_domain} which extracts the domain name from the From: -Header",
                'default': "/etc/fuglu/dkim/${header_from_domain}.key",
            },

            'canonicalizeheaders': {
                'description': "Type of header canonicalization (simple or relaxed)",
                'default': "relaxed",
            },

            'canonicalizebody': {
                'description': "Type of body canonicalization (simple or relaxed)",
                'default': "relaxed",
            },

            'selector': {
                'description': 'selector to use when signing, supports templates',
                'default': 'default',
            },

            'signheaders': {
                'description': 'comma separated list of headers to sign. empty string=sign all headers',
                'default': 'From,Reply-To,Subject,Date,To,CC,Resent-Date,Resent-From,Resent-To,Resent-CC,In-Reply-To,References,List-Id,List-Help,List-Unsubscribe,List-Subscribe,List-Post,List-Owner,List-Archive',
            },

            'signbodylength': {
                'description': 'include l= tag in dkim header',
                'default': 'False',
            },
        }

    def __str__(self):
        return "DKIM Sign"

    def get_header_from_domain(self, suspect):
        """extract the header from domain. Returns None if extraction fails or if there are multiple from headers"""
        msgrep = suspect.get_message_rep()
        from_headers = msgrep.get_all("From")
        if len(from_headers) != 1:
            return None

        from_header = from_headers[0]
        domain_match = re.search("(?<=@)[\w.-]+", from_header)
        if domain_match == None:
            return None
        domain = domain_match.group()
        return domain

    def examine(self, suspect):
        if not DKIMPY_AVAILABLE:
            suspect.debug("dkimpy not available, can not check")
            self._logger().error(
                "DKIM signing skipped - missing dkimpy library")
            return DUNNO

        message = suspect.get_source()
        domain = self.get_header_from_domain(suspect)
        addvalues = dict(header_from_domain=domain)
        selector = apply_template(
            self.config.get(self.section, 'selector'), suspect, addvalues)

        if domain == None:
            self._logger().error(
                "%s: Failed to extract From-header domain for DKIM signing" % suspect.id)
            return DUNNO

        privkeyfile = apply_template(
            self.config.get(self.section, 'privatekeyfile'), suspect, addvalues)
        if not os.path.isfile(privkeyfile):
            self._logger().error("%s: DKIM signing failed for domain %s, private key not found: %s" %
                                 (suspect.id, domain, privkeyfile))
            return DUNNO
        privkeycontent = open(privkeyfile, 'r').read()

        canH = Simple
        canB = Simple

        if self.config.get(self.section, 'canonicalizeheaders').lower() == 'relaxed':
            canH = Relaxed
        if self.config.get(self.section, 'canonicalizebody').lower() == 'relaxed':
            canB = Relaxed
        canon = (canH, canB)
        headerconfig = self.config.get(self.section, 'signheaders')
        if headerconfig == None or headerconfig.strip() == '':
            inc_headers = None
        else:
            inc_headers = headerconfig.strip().split(',')

        blength = self.config.getboolean(self.section, 'signbodylength')

        dkimhdr = sign(message, selector, domain, privkeycontent, canonicalize=canon,
                       include_headers=inc_headers, length=blength, logger=suspect.get_tag('debugfile'))
        if dkimhdr.startswith('DKIM-Signature: '):
            dkimhdr = dkimhdr[16:]

        suspect.addheader('DKIM-Signature', dkimhdr, immediate=True)

    def lint(self):
        if not DKIMPY_AVAILABLE:
            print("Missing dependency: dkimpy https://launchpad.net/dkimpy")
            print("(also requires either dnspython or pydns)")
            return False

        # if privkey is a filename (no placeholders) check if it exists
        privkeytemplate = self.config.get(self.section, 'privatekeyfile')
        if '{' not in privkeytemplate and not os.path.exists(privkeytemplate):
            print("Private key file %s not found" % privkeytemplate)
            return False

        return self.checkConfig()


class SPFPlugin(ScannerPlugin):

    """**EXPERIMENTAL**
This plugin checks the SPF status and sets tag 'SPF.status' to one of the official states 'pass', 'fail', 'neutral',
'softfail, 'permerror', 'temperror' or 'skipped' if the SPF check could not be peformed.
Tag 'SPF.explanation' contains a human readable explanation of the result

The plugin does not take any action based on the SPF test result since. Other plugins might use the SPF result
in combination with other factors to take action (for example a "DMARC" plugin could use this information)
    """

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {

        }
        self.logger = self._logger()

    def __str__(self):
        return "SPF Check"

    def examine(self, suspect):
        if not PYSPF_AVAILABLE:
            suspect.debug("pyspf not available, can not check")
            self._logger().warning(
                "%s: SPF Check skipped, pyspf unavailable" % (suspect.id))
            suspect.set_tag('SPF.status', 'skipped')
            suspect.set_tag("SPF.explanation", 'missing dependency')
            return DUNNO

        clientinfo = suspect.get_client_info(self.config)
        if clientinfo == None:
            suspect.debug("client info not available for SPF check")
            self._logger().warning(
                "%s: SPF Check skipped, could not get client info" % (suspect.id))
            suspect.set_tag('SPF.status', 'skipped')
            suspect.set_tag(
                "SPF.explanation", 'could not extract client information')
            return DUNNO

        helo, ip, revdns = clientinfo
        result, explanation = spf.check2(ip, suspect.from_address, helo)
        suspect.set_tag("SPF.status", result)
        suspect.set_tag("SPF.explanation", explanation)
        suspect.debug("SPF status: %s (%s)" % (result, explanation))
        return DUNNO

    def lint(self):
        if not PYSPF_AVAILABLE:
            print("Missing dependency: pyspf")
            print("(also requires pydns and ipaddress or ipaddr)")
            return False

        return self.checkConfig()


class DomainAuthPlugin(ScannerPlugin):

    """**EXPERIMENTAL**
This plugin checks the header from domain against a list of domains which must be authenticated by DKIM and/or SPF.
This is somewhat similar to DMARC but instead of asking the sender domain for a DMARC policy record this plugin allows you to force authentication on the recipient side.

This plugin depends on tags written by SPFPlugin and DKIMVerifyPlugin, so they must run beforehand.
    """

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {
            'domainsfile': {
                'description': "File containing a list of domains (one per line) which must be DKIM and/or SPF authenticated",
                'default': "/etc/fuglu/auth_required_domains.txt",
            },
            'failaction': {
                'default': 'DUNNO',
                'description': "action if the message doesn't pass authentication (DUNNO, REJECT)",
            },

            'rejectmessage': {
                'default': 'sender domain ${header_from_domain} must pass DKIM and/or SPF authentication',
                'description': "reject message template if running in pre-queue mode",
            },
        }
        self.logger = self._logger()
        self.filelist = FileList(
            filename=None, strip=True, skip_empty=True, skip_comments=True, lowercase=True)

    def examine(self, suspect):
        self.filelist.filename = self.config.get(self.section, 'domainsfile')
        checkdomains = self.filelist.get_list()

        envelope_sender_domain = suspect.from_domain.lower()
        header_from_domain = self.extract_from_domain(suspect)
        if header_from_domain == None:
            return

        if header_from_domain not in checkdomains:
            return

        # TODO: do we need a tag from dkim to check if the verified dkim domain
        # actually matches the header from domain?
        dkimresult = suspect.get_tag('DKIMVerify.sigvalid', False)
        if dkimresult == True:
            return DUNNO

        # DKIM failed, check SPF if envelope senderdomain belongs to header
        # from domain
        spfresult = suspect.get_tag('SPF.status', 'unknown')
        if (envelope_sender_domain == header_from_domain or envelope_sender_domain.endswith('.%s' % header_from_domain)) and spfresult == 'pass':
            return DUNNO

        failaction = self.config.get(self.section, 'failaction')
        actioncode = string_to_actioncode(failaction, self.config)

        values = dict(
            header_from_domain=header_from_domain)
        message = apply_template(
            self.config.get(self.section, 'rejectmessage'), suspect, values)
        return actioncode, message

    def flag_as_spam(self, suspect):
        suspect.tags['spam']['domainauth'] = True

    def extract_from_domain(self, suspect):
        """
        Try to extract from header domain
        """
        try:
            msgrep = suspect.get_message_rep()
            address = msgrep.get('From')
            if address == None:
                return None

            start = address.find('<') + 1
            if start < 1:
                start = address.find(':') + 1

            if start >= 0:
                end = string.find(address, '>')
                if end < 0:
                    end = len(address)
            retaddr = address[start:end]
            retaddr = retaddr.strip()

            if '@' not in retaddr:
                return None

            domain = retaddr.split('@', 1)[1]

            return domain.lower()
        except:
            return None

    def __str__(self):
        return "DomainAuth"

    def lint(self):
        allok = (self.checkConfig() and self.lint_file())
        return allok

    def lint_file(self):
        filename = self.config.get(self.section, 'domainsfile')
        if not os.path.exists(filename):
            print("domains file %s not found" % (filename))
            return False
        return True
