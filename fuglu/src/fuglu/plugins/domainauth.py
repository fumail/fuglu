# -*- coding: UTF-8 -*-
#   Copyright 2009-2018 Oli Schacher
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

from fuglu.shared import ScannerPlugin, apply_template, DUNNO, FileList, string_to_actioncode, get_default_cache
from fuglu.extensions.sql import get_session, SQL_EXTENSION_ENABLED
from fuglu.extensions.dnsquery import HAVE_PYDNS, HAVE_DNSPYTHON
import logging
import os
import re

DKIMPY_AVAILABLE = False
PYSPF_AVAILABLE = False
IPADDRESS_AVAILABLE = False
IPADDR_AVAILABLE = False

try:
    import ipaddress
    IPADDRESS_AVAILABLE = True
except ImportError:
    pass

try:
    import ipaddr
    IPADDR_AVAILABLE = True
except ImportError:
    pass

try:
    import pkg_resources
    pkg_resources.get_distribution("dkimpy")
    from dkim import DKIM, sign, Simple, Relaxed, DKIMException

    if not (HAVE_PYDNS or HAVE_DNSPYTHON):
        raise Exception("no supported dns library available")

    DKIMPY_AVAILABLE = True
except Exception:
    pass


try:
    if not HAVE_PYDNS:
        raise Exception("pydns not available")
    if not (IPADDR_AVAILABLE or IPADDRESS_AVAILABLE):
        raise Exception("ipaddress/ipaddr not available")
    import spf
    PYSPF_AVAILABLE = True
except Exception as e:
    print(e)
    pass


def extract_from_domain(suspect, get_address_part=True):
    msgrep = suspect.get_message_rep()
    from_headers = msgrep.get_all("From", [])
    if len(from_headers) != 1:
        return None

    from_header = from_headers[0]
    parts = from_header.rsplit(None, 1)
    check_part = parts[-1]
    if len(parts) == 2 and not get_address_part:
        check_part = parts[0]
    elif not get_address_part:
        return None # no display part found
    
    domain_match = re.search("(?<=@)[\w.-]+", check_part)
    if domain_match is None:
        return None
    domain = domain_match.group()
    return domain


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

        return self.check_config()

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

    def examine(self, suspect):
        if not DKIMPY_AVAILABLE:
            suspect.debug("dkimpy not available, can not check")
            self._logger().error(
                "DKIM signing skipped - missing dkimpy library")
            return DUNNO

        message = suspect.get_source()
        domain = extract_from_domain(suspect)
        addvalues = dict(header_from_domain=domain)
        selector = apply_template(
            self.config.get(self.section, 'selector'), suspect, addvalues)

        if domain is None:
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
        if headerconfig is None or headerconfig.strip() == '':
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

        return self.check_config()


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
        if clientinfo is None:
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

        return self.check_config()


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
        header_from_domain = extract_from_domain(suspect)
        if header_from_domain is None:
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

    def __str__(self):
        return "DomainAuth"

    def lint(self):
        allok = self.check_config() and self.lint_file()
        return allok

    def lint_file(self):
        filename = self.config.get(self.section, 'domainsfile')
        if not os.path.exists(filename):
            print("domains file %s not found" % (filename))
            return False
        return True


class SpearPhishPlugin(ScannerPlugin):
    """Mark spear phishing mails as virus

    The spearphish plugin checks if the sender domain in the "From"-Header matches the envelope recipient Domain ("Mail
    from my own domain") but the message uses a different envelope sender domain. This blocks many spearphish attempts.

    Note that this plugin can cause blocks of legitimate mail , for example if the recipient domain is using a third party service
    to send newsletters in their name. Such services often set the customers domain in the from headers but use their own domains in the envelope for
    bounce processing. Use the 'Plugin Skipper' or any other form of whitelisting in such cases.
    """

    def __init__(self, section=None):
        ScannerPlugin.__init__(self, section)
        self.logger = self._logger()
        self.filelist = FileList(strip=True, skip_empty=True, skip_comments=True, lowercase=True,
                                 additional_filters=None, minimum_time_between_reloads=30)

        self.requiredvars = {
            'domainsfile': {
                'default': '/etc/fuglu/spearphish-domains',
                'description': 'Filename where we load spearphish domains from. One domain per line. If this setting is empty, the check will be applied to all domains.',
            },
            'virusenginename': {
                'default': 'Fuglu SpearPhishing Protection',
                'description': 'Name of this plugins av engine',
            },
            'virusname': {
                'default': 'TRAIT.SPEARPHISH',
                'description': 'Name to use as virus signature',
            },
            'virusaction': {
                'default': 'DEFAULTVIRUSACTION',
                'description': "action if spear phishing attempt is detected (DUNNO, REJECT, DELETE)",
            },
            'rejectmessage': {
                'default': 'threat detected: ${virusname}',
                'description': "reject message template if running in pre-queue mode and virusaction=REJECT",
            },
            'dbconnection':{
                'default':"mysql://root@localhost/spfcheck?charset=utf8",
                'description':'SQLAlchemy Connection string. Leave empty to disable SQL lookups',
            },
            'domain_sql_query':{
                'default':"SELECT check_spearphish from domain where domain_name=:domain",
                'description':'get from sql database :domain will be replaced with the actual domain name. must return boolean field check_spearphish',
            },
            'check_display_part': {
                'default': 'False',
                'description': "set to True to also check display part of From header (else email part only)",
            },
        }


    def get_domain_setting(self, domain, dbconnection, sqlquery, cache, cachename, default_value=None, logger=None):
        if logger is None:
            logger = logging.getLogger()
        
        cachekey = '%s-%s' % (cachename, domain)
        cached = cache.get_cache(cachekey)
        if cached is not None:
            logger.debug("got cached setting for %s" % domain)
            return cached
    
        settings = default_value
    
        try:
            session = get_session(dbconnection)
    
            # get domain settings
            dom = session.execute(sqlquery, {'domain': domain}).fetchall()
    
            if not dom and not dom[0] and len(dom[0]) == 0:
                logger.warning(
                    "Can not load domain setting - domain %s not found. Using default settings." % domain)
            else:
                settings = dom[0][0]
    
            session.close()
    
        except Exception as e:
            logger.error("Exception while loading setting for %s : %s" % (domain, str(e)))
    
        cache.put_cache(cachekey, settings)
        logger.debug("refreshed setting for %s" % domain)
        return settings
    
    
    def should_we_check_this_domain(self,suspect):
        domainsfile = self.config.get(self.section, 'domainsfile')
        if domainsfile.strip()=='': # empty config -> check all domains
            return True

        if not os.path.exists(domainsfile):
            return False

        self.filelist.filename = domainsfile
        envelope_recipient_domain = suspect.to_domain.lower()
        checkdomains = self.filelist.get_list()
        if envelope_recipient_domain in checkdomains:
            return True
        
        dbconnection = self.config.get(self.section, 'dbconnection').strip()
        sqlquery = self.config.get(self.section,'domain_sql_query')
        do_check = False
        if dbconnection != '':
            cache = get_default_cache()
            cachename = self.section
            do_check = self.get_domain_setting(suspect.to_domain, dbconnection, sqlquery, cache, cachename, False, self.logger)
        return do_check
    
    
    def examine(self, suspect):
        if not self.should_we_check_this_domain(suspect):
            return DUNNO
        envelope_recipient_domain = suspect.to_domain.lower()
        envelope_sender_domain = suspect.from_domain.lower()
        if envelope_sender_domain == envelope_recipient_domain:
            return DUNNO  # we only check the message if the env_sender_domain differs. If it's the same it will be caught by other means (like SPF)
        
        header_from_domains = []
        header_from_domain = extract_from_domain(suspect)
        if header_from_domain is None:
            self.logger.warn("%s: Could not extract header from domain for spearphish check" % suspect.id)
            return DUNNO
        else:
            header_from_domains.append(header_from_domain)
            self.logger.debug('%s: checking domain %s (source: From header address part)' % (suspect.id, header_from_domain))
        
        if self.config.getboolean(self.section, 'check_display_part'):
            display_from_domain = extract_from_domain(suspect, False)
            if display_from_domain is not None and display_from_domain not in header_from_domains:
                header_from_domains.append(display_from_domain)
                self.logger.debug('%s: checking domain %s (source: From header display part)' % (suspect.id, display_from_domain))
        
        actioncode = DUNNO
        message = None
        
        for header_from_domain in header_from_domains:
            if header_from_domain == envelope_recipient_domain:
                virusname = self.config.get(self.section, 'virusname')
                virusaction = self.config.get(self.section, 'virusaction')
                actioncode = string_to_actioncode(virusaction, self.config)
                
                logmsg = '%s: spear phish pattern detected, env_rcpt_domain=%s env_sender_domain=%s header_from_domain=%s' % \
                         (suspect.id, envelope_recipient_domain, envelope_sender_domain, header_from_domain)
                self.logger.info(logmsg)
                self.flag_as_phish(suspect, virusname)
                
                message = apply_template(self.config.get(self.section, 'rejectmessage'), suspect, {'virusname': virusname})
                break
        
        return actioncode, message
    
    
    def flag_as_phish(self, suspect, virusname):
        suspect.tags['%s.virus' % self.config.get(self.section, 'virusenginename')] = {'message content': virusname}
        suspect.tags['virus'][self.config.get(self.section, 'virusenginename')] = True
    
    
    def __str__(self):
        return "Spearphish Check"
    
    
    def lint(self):
        allok = self.check_config() and self._lint_file() and self._lint_sql()
        return allok
    
    
    def _lint_file(self):
        filename = self.config.get(self.section, 'domainsfile')
        if not os.path.exists(filename):
            print("Spearphish domains file %s not found" % filename)
            return False
        return True
    
    
    def _lint_sql(self):
        lint_ok = True
        sqlquery = self.config.get(self.section, 'domain_sql_query')
        dbconnection = self.config.get(self.section, 'dbconnection').strip()
        if not SQL_EXTENSION_ENABLED and dbconnection != '':
            print('SQLAlchemy not available, cannot use SQL backend')
            lint_ok = False
        elif dbconnection == '':
            print('No DB connection defined. Disabling SQL backend')
        else:
            if not sqlquery.lower().startswith('select '):
                lint_ok = False
                print('SQL statement must be a SELECT query')
            if lint_ok:
                try:
                    conn = get_session(dbconnection)
                    conn.execute(sqlquery, {'domain': 'example.com'})
                except Exception as e:
                    lint_ok = False
                    print(str(e))
        return lint_ok
    
    
    