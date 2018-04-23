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
#
#
import logging
import os
import sys
import time
import socket
import uuid
import threading
from fuglu.localStringEncoding import force_uString, force_bString
try:
    from html.parser import HTMLParser
except ImportError:
    from HTMLParser import HTMLParser

HAVE_BEAUTIFULSOUP = False
BS_VERSION = 0
try:
    import bs4 as BeautifulSoup
    HAVE_BEAUTIFULSOUP = True
    BS_VERSION = 4
except ImportError:
    pass

if not HAVE_BEAUTIFULSOUP:
    try:
        import BeautifulSoup
        HAVE_BEAUTIFULSOUP = True
        BS_VERSION = 3
    except ImportError:
        pass

import email
import re
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
import datetime
from string import Template
from email.header import Header

# constants

DUNNO = 0  # go on
ACCEPT = 1  # accept message, no further tests
DELETE = 2  # blackhole, no further tests
REJECT = 3  # reject, no further tests
DEFER = 4  # defer, no further tests

ALLCODES = {
    'DUNNO': DUNNO,
    'ACCEPT': ACCEPT,
    'DELETE': DELETE,
    'REJECT': REJECT,
    'DEFER': DEFER,
}


def actioncode_to_string(actioncode):
    """Return the human readable string for this code"""
    for key, val in list(ALLCODES.items()):
        if val == actioncode:
            return key
    if actioncode is None:
        return "NULL ACTION CODE"
    return 'INVALID ACTION CODE %s' % actioncode


def string_to_actioncode(actionstring, config=None):
    """return the code for this action"""
    upper = actionstring.upper().strip()

    # support DISCARD as alias for DELETE
    if upper == 'DISCARD':
        upper = 'DELETE'

    if config is not None:
        if upper == 'DEFAULTHIGHSPAMACTION':
            confval = config.get('spam', 'defaulthighspamaction').upper()
            if confval not in ALLCODES:
                return None
            return ALLCODES[confval]

        if upper == 'DEFAULTLOWSPAMACTION':
            confval = config.get('spam', 'defaultlowspamaction').upper()
            if confval not in ALLCODES:
                return None
            return ALLCODES[confval]

        if upper == 'DEFAULTVIRUSACTION':
            confval = config.get('virus', 'defaultvirusaction').upper()
            if confval not in ALLCODES:
                return None
            return ALLCODES[confval]

    if upper not in ALLCODES:
        return None
    return ALLCODES[upper]


def apply_template(templatecontent, suspect, values=None, valuesfunction=None):
    """Replace templatecontent variables as defined in http://fumail.github.io/fuglu/plugins-index.html#template-variables
    with actual values from suspect
    the calling function can pass additional values by passing a values dict

    if valuesfunction is not none, it is called with the final dict with all built-in and passed values
    and allows further modifications, like SQL escaping etc
    """
    if values is None:
        values = {}

    default_template_values(suspect, values)

    if valuesfunction is not None:
        values = valuesfunction(values)

    template = Template(force_uString(templatecontent))

    message = template.safe_substitute(values)
    return message


def default_template_values(suspect, values=None):
    """Return a dict with default template variables applicable for this suspect
    if values is not none, fill the values dict instead of returning a new one"""

    if values is None:
        values = {}

    values['id'] = suspect.id
    values['timestamp'] = suspect.timestamp
    values['from_address'] = suspect.from_address
    values['to_address'] = suspect.to_address
    values['from_domain'] = suspect.from_domain
    values['to_domain'] = suspect.to_domain
    values['subject'] = suspect.get_message_rep()['subject']
    values['date'] = str(datetime.date.today())
    values['time'] = time.strftime('%X')
    return values

HOSTNAME = socket.gethostname()


def yesno(val):
    """returns the string 'yes' for values that evaluate to True, 'no' otherwise"""
    if val:
        return 'yes'
    else:
        return 'no'


class Suspect(object):

    """
    The suspect represents the message to be scanned. Each scannerplugin will be presented
    with a suspect and may modify the tags or even the message content itself.
    """

    def __init__(self, from_address, recipients, tempfile):
        self.source = None
        """holds the message source if set directly"""

        self._msgrep = None
        """holds a copy of the message representation"""

        # tags set by plugins
        self.tags = {}
        self.tags['virus'] = {}
        self.tags['blocked'] = {}
        self.tags['spam'] = {}
        self.tags['highspam'] = {}
        self.tags['decisions'] = []
        self.tags['scantimes'] = []

        # temporary file containing the message source
        self.tempfile = tempfile

        # stuff set from smtp transaction
        self.size = os.path.getsize(tempfile)
        self.from_address = from_address

        # backwards compatibility, recipients can be a single address
        if isinstance(recipients, list):
            self.recipients = recipients
        else:
            self.recipients = [recipients, ]

        # basic email validitiy check - nothing more than necessary for our internal assumptions
        for rec in self.recipients:
            if rec is None:
                raise ValueError("Recipient address can not be None")
            if not re.match(r"[^@]+@[^@]+$", rec):
                raise ValueError("Invalid recipient address: %s"%rec)


        # additional basic information
        self.timestamp = time.time()
        self.id = self._generate_id()

        # headers which are prepended before re-injecting the message
        self.addheaders = {}

        if self.from_address is None:
            self.from_address = ''

        if self.from_address!='' and  not re.match(r"[^@]+@[^@]+$", self.from_address):
            raise ValueError("invalid sender address: %s"%self.from_address)

        self.clientinfo = None
        """holds client info tuple: helo, ip, reversedns"""

    @property
    def to_address(self):
        """Returns the first recipient address"""
        try:
            return self.recipients[0]
        except IndexError:
            return None

    @to_address.setter
    def to_address(self, recipient):
        """Sets a single recipient for this suspect, removing all others"""
        self.recipients=[recipient,]

    @property
    def to_localpart(self):
        """Returns the local part of the first recipient"""
        try:
            return self.to_address.rsplit('@', 1)[0]
        except Exception:
            logging.getLogger('suspect').error('could not extract localpart from recipient address %s' % self.to_address)
            return None

    @property
    def to_domain(self):
        """Returns the local part of the first recipient"""
        try:
            return self.to_address.rsplit('@', 1)[1]
        except Exception:
            logging.getLogger('suspect').error('could not extract domain from recipient address %s' % self.from_address)
            return None


    @property
    def from_localpart(self):
        if self.from_address == '':
            return ''

        else:
            try:
               return self.from_address.rsplit('@', 1)[0]
            except Exception:
                logging.getLogger('suspect').error('could not extract localpart from sender address %s'%self.from_address)
                return None

    @property
    def from_domain(self):
        if self.from_address == '':
            return ''

        else:
            try:
                return self.from_address.rsplit('@', 1)[1]
            except Exception:
                logging.getLogger('suspect').error('could not extract domain from sender address %s' % self.from_address)
                return None


    def _generate_id(self):
        """
        returns a unique id (a string of 32 hex characters)
        """
        return uuid.uuid4().hex

    def debug(self, message):
        """Add a line to the debug log if debugging is enabled for this message"""
        if not self.get_tag('debug'):
            return
        isotime = datetime.datetime.now().isoformat()
        fp = self.get_tag('debugfile')
        try:
            fp.write('%s %s\n' % (isotime, message))
            fp.flush()
        except Exception as e:
            logging.getLogger('suspect').error(
                'Could not write to logfile: %s' % e)

    def get_tag(self, key, defaultvalue=None):
        """returns the tag value. if the tag is not found, return defaultvalue instead (None if no defaultvalue passed)"""
        if key not in self.tags:
            return defaultvalue
        return self.tags[key]

    def set_tag(self, key, value):
        """Set a new tag"""
        self.tags[key] = value

    def is_highspam(self):
        """Returns True if ANY of the spam engines tagged this suspect as high spam"""
        for key in list(self.tags['highspam'].keys()):
            val = self.tags['highspam'][key]
            if val:
                return True
        return False

    def is_spam(self):
        """Returns True if ANY of the spam engines tagged this suspect as spam"""
        for key in list(self.tags['spam'].keys()):
            val = self.tags['spam'][key]
            if val:
                return True
        return False
    
    def is_blocked(self):
        """Returns True if ANY plugin tagged this suspect as blocked"""
        for key in list(self.tags['blocked'].keys()):
            val = self.tags['blocked'][key]
            if val:
                return True
        return False

    def is_virus(self):
        """Returns True if ANY of the antivirus engines tagged this suspect as infected"""
        for key in list(self.tags['virus'].keys()):
            val = self.tags['virus'][key]
            if val:
                return True
        return False
    
    def is_ham(self):
        """Returns True if message is neither considered to be spam, virus or blocked"""
        if self.is_spam() or self.is_virus() or self.is_blocked() or self.is_highspam():
            return False
        return True
    
    def update_subject(self, subject_cb, **cb_params):
        """
        update/alter the message subject
        :param subject_cb: callback function that alters the subject. must accept a string and return a string
        :param cb_params: additional parameters to be passed to subject_cb
        :return: True if subject was altered, False otherwise
        """
        msgrep = self.get_message_rep()
        oldsubj = msgrep.get("subject","")
        newsubj = subject_cb(oldsubj, **cb_params)
        if oldsubj != newsubj:
            del msgrep["subject"]
            msgrep["subject"] = newsubj
            self.set_message_rep(msgrep)
            if self.get_tag('origsubj') is None:
                self.set_tag('origsubj', oldsubj)
            return True
        return False


    def add_header(self, key, value, immediate=False):
        """adds a header to the message. by default, headers will added when re-injecting the message back to postfix
        if you set immediate=True the message source will be replaced immediately. Only set this to true if a header must be
        visible to later plugins (eg. for spamassassin rules), otherwise, leave as False which is faster.
        """
        if immediate:
            # is ignore the right thing to do here?
            value = value.encode('UTF-8', 'ignore')
            hdr = Header(value, header_name=key, continuation_ws=' ')
            hdrline = "%s: %s\n" % (key, hdr.encode())
            src = force_bString(hdrline) + force_bString(self.get_source())
            self.set_source(src)
        else:
            self.addheaders[key] = value

    def addheader(self, key, value, immediate=False):
        """old name for add_header"""
        return self.add_header(key, value, immediate)

    def get_current_decision_code(self):
        dectag = self.get_tag('decisions')
        if dectag is None:
            return DUNNO
        try:
            pluginname, code = dectag[-1]
            return code
        except Exception:
            return DUNNO

    def _short_tag_rep(self):
        """return a tag representation suitable for logging, with some tags stripped, some shortened"""
        blacklist = ['decisions', 'scantimes', 'debugfile']
        tagscopy = {}

        for k, v in self.tags.items():
            if k in blacklist:
                continue

            try:
                strrep = str(v)
            except Exception:  # Unicodedecode errors and stuff like that
                continue

            therep = v

            maxtaglen = 100
            if len(strrep) > maxtaglen:
                therep = strrep[:maxtaglen] + "..."

            # specialfixes
            if k == 'SAPlugin.spamscore' and not isinstance(v, str):
                therep = "%.2f" % v

            tagscopy[k] = therep
        return str(tagscopy)

    def log_format(self, template=None):
        addvals = {
            'size': self.size,
            'spam': yesno(self.is_spam()),
            'highspam': yesno(self.is_highspam()),
            'blocked': yesno(self.is_blocked()),
            'virus': yesno(self.is_virus()),
            'modified': yesno(self.is_modified()),
            'decision': actioncode_to_string(self.get_current_decision_code()),
            'tags': self._short_tag_rep(),
            'fulltags': str(self.tags),
        }
        return apply_template(template, self, addvals)

    def __str__(self):
        """representation good for logging"""
        return self.log_format("Suspect ${id}: from=${from_address} to=${to_address} size=${size} spam=${spam} blocked=${blocked} virus=${virus} modified=${modified} decision=${decision} tags=${tags}")

    def get_message_rep(self):
        """returns the python email api representation of this suspect"""
        # do we have a cached instance already?
        if self._msgrep is not None:
            return self._msgrep
        
        if self.source is not None:
            if sys.version_info > (3,):
                # Python 3 and larger
                # the basic "str" type is unicode
                if isinstance(self.source, str):
                    msgrep = email.message_from_string(self.source)
                else:
                    msgrep = email.message_from_bytes(self.source)
            else:
                # Python 2.x
                msgrep = email.message_from_string(self.source)
        
            self._msgrep = msgrep
            return msgrep
        else:
            if sys.version_info > (3,):
                # Python 3 and larger
                # file should be binary...
        
                # IMPORTANT: It is possible to use email.message_from_bytes BUT this will automatically replace
                #            '\r\n' in the message (_payload) by '\n' and the endtoend_test.py will fail!
                tmpSource = self.get_original_source()
                msgrep = email.message_from_bytes(tmpSource)
            else:
                # Python 2.x
                with open(self.tempfile, 'r') as fh:
                    msgrep = email.message_from_file(fh)
            self._msgrep = msgrep
            return msgrep

    def getMessageRep(self):
        """old name for get_message_rep"""
        return self.get_message_rep()

    def set_message_rep(self, msgrep):
        """replace the message content. this must be a standard python email representation
        Warning: setting the source via python email representation seems to break dkim signatures!
        """
        if sys.version_info > (3,):
            # Python 3 and larger
            # stick to bytes...
            try:
                self.set_source(msgrep.as_bytes())
            except AttributeError:
                self.set_source(force_bString(msgrep.as_string()))
        else:
            # Python 2.x
            self.set_source(msgrep.as_string())
    
        # order is important, set_source sets source to None
        self._msgrep = msgrep

    def setMessageRep(self, msgrep):
        """old name for set_message_rep"""
        return self.set_message_rep(msgrep)

    def is_modified(self):
        """returns true if the message source has been modified"""
        return self.source is not None

    def get_source(self, maxbytes=None):
        """returns the current message source, possibly changed by plugins"""
        if self.source is not None:
            return self.source[:maxbytes]
        else:
            return self.get_original_source(maxbytes)

    def getSource(self, maxbytes=None):
        """old name for get_source"""
        return self.get_source(maxbytes)

    def set_source(self, source):
        self.source = source
        self._msgrep = None

    def setSource(self, source):
        """old name for set_source"""
        return self.set_source(source)

    def get_original_source(self, maxbytes=None):
        """returns the original, unmodified message source"""
        readbytes = -1
        if maxbytes is not None:
            readbytes = maxbytes
        try:
            with open(self.tempfile, 'rb') as fh:
                source = fh.read(readbytes)
        except Exception as e:
            logging.getLogger('fuglu.suspect').error(
                'Cannot retrieve original source from tempfile %s : %s' % (self.tempfile, str(e)))
            raise e
        return source

    def getOriginalSource(self, maxbytes=None):
        """old name for get_original_source"""
        return self.get_original_source(maxbytes)

    def get_headers(self):
        """returns the message headers as string"""
        headers = re.split(
            b'(?:\n\n)|(?:\r\n\r\n)', self.get_source(maxbytes=1048576), 1)[0]
        return headers

    def get_client_info(self, config=None):
        """returns information about the client that submitted this message.
        (helo,ip,reversedns)

        In before-queue mode this info is extracted using the XFORWARD SMTP protocol extension.

        In after-queue mode this information is extracted from the message Received: headers and therefore probably not 100% reliable
        all information is returned as-is, this means for example, that non-fcrdns client will show 'unknown' as reverse dns value.

        if no config object is passed, the first parseable Received header is used. otherwise, the config is used to determine the correct boundary MTA (trustedhostregex / boundarydistance)
        """
        if self.clientinfo is not None:
            return self.clientinfo

        if config is None:
            clientinfo = self.client_info_from_rcvd()

        else:
            clientinfo = self.client_info_from_rcvd(config.get(
                'environment', 'trustedhostsregex'), config.getint('environment', 'boundarydistance'))
        self.clientinfo = clientinfo
        return clientinfo

    def client_info_from_rcvd(self, ignoreregex=None, skip=0):
        """returns information about the client that submitted this message.
        (helo,ip,reversedns)

        This information is extracted from the message Received: headers and therefore probably not 100% reliable
        all information is returned as-is, this means for example, that non-fcrdns client will show 'unknown' as reverse dns value.

        if ignoreregex is not None, all results which match this regex in either helo,ip or reversedns will be ignored

        By default, this method starts searching at the top Received Header. Set a higher skip value to start searching further down.

        both these arguments can be used to filter received headers from local systems in order to get the information from a boundary MTA

        returns None if the client info can not be found or if all applicable values are filtered by skip/ignoreregex
        """
        ignorere = None
        if ignoreregex is not None and ignoreregex != '':
            ignorere = re.compile(ignoreregex)

        unknown = None

        receivedheaders = self.get_message_rep().get_all('Received')
        if receivedheaders is None:
            return unknown

        for rcvdline in receivedheaders[skip:]:
            h_rev_ip = self._parse_rcvd_header(rcvdline)
            if h_rev_ip is None:
                return unknown

            helo, revdns, ip = h_rev_ip

            # check if hostname or ip matches the ignore re, try next header if
            # it does
            if ignorere is not None:
                excludematch = ignorere.search(ip)
                if excludematch is not None:
                    continue

                excludematch = ignorere.search(revdns)
                if excludematch is not None:
                    continue

                excludematch = ignorere.search(helo)
                if excludematch is not None:
                    continue

            clientinfo = helo, ip, revdns
            return clientinfo
        # we should only land here if we only have received headers in
        # mynetworks
        return unknown

    def _parse_rcvd_header(self, rcvdline):
        """return tuple HELO,REVERSEDNS,IP from received Header line, or None, if extraction fails"""
        receivedpattern = re.compile(
            "^from\s(?P<helo>[^\s]+)\s\((?P<revdns>[^\s]+)\s\[(?:IPv6:)?(?P<ip>(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:[0-9a-f:]{3,40}))\]\)")
        match = receivedpattern.search(rcvdline)
        if match is None:
            return None
        return match.groups()


# it is important that this class explicitly extends from object, or
# __subclasses__() will not work!


class BasicPlugin(object):

    """Base class for all plugins"""

    def __init__(self, config, section=None):
        if section is None:
            self.section = self.__class__.__name__
        else:
            self.section = section

        self.config = config
        self.requiredvars = {}

    def _logger(self):
        """returns the logger for this plugin"""
        myclass = self.__class__.__name__
        loggername = "fuglu.plugin.%s" % myclass
        return logging.getLogger(loggername)

    def lint(self):
        return self.checkConfig()

    def checkConfig(self):
        """old name for check_config"""
        return self.check_config()

    def check_config(self):
        """Print missing / non-default configuration settings"""
        allOK = True

        # old config style
        if isinstance(self.requiredvars, (tuple, list)):
            for configvar in self.requiredvars:
                if isinstance(self.requiredvars, tuple):
                    (section, config) = configvar
                else:
                    config = configvar
                    section = self.section
                try:
                    self.config.get(section, config)
                except configparser.NoOptionError:
                    print("Missing configuration value [%s] :: %s" % (
                        section, config))
                    allOK = False
                except configparser.NoSectionError:
                    print("Missing configuration section %s" % section)
                    allOK = False

        # new config style
        if isinstance(self.requiredvars, dict):
            for config, infodic in self.requiredvars.items():
                section = self.section
                if 'section' in infodic:
                    section = infodic['section']

                try:
                    var = self.config.get(section, config)
                    if 'validator' in infodic:
                        if not infodic["validator"](var):
                            print("Validation failed for [%s] :: %s" % (
                                section, config))
                            allOK = False
                except configparser.NoSectionError:
                    print("Missing configuration section [%s] :: %s" % (
                        section, config))
                    allOK = False
                except configparser.NoOptionError:
                    print("Missing configuration value [%s] :: %s" % (
                        section, config))
                    allOK = False

        return allOK

    def __str__(self):
        classname = self.__class__.__name__
        if self.section == classname:
            return classname
        else:
            return '%s(%s)' % (classname, self.section)


class ScannerPlugin(BasicPlugin):

    """Scanner Plugin Base Class"""

    def examine(self, suspect):
        self._logger().warning('Unimplemented examine() method')


class PrependerPlugin(BasicPlugin):

    """Prepender Plugins - Plugins run before the scanners that can influence
    the list of scanners being run for a certain message"""

    def pluginlist(self, suspect, pluginlist):
        """return the modified pluginlist or None for no change"""
        self._logger().warning('Unimplemented pluginlist() method')
        return None


class AppenderPlugin(BasicPlugin):

    """Appender Plugins are run after the scan process (and after the re-injection if the message
    was accepted)"""

    def process(self, suspect, decision):
        self._logger().warning('Unimplemented process() method')


class SuspectFilter(object):

    """Allows filtering Suspect based on header/tag/body regexes"""

    def __init__(self, filename):
        self.filename = filename
        self.patterns = []

        self.reloadinterval = 30
        self.lastreload = 0
        self.logger = logging.getLogger('fuglu.suspectfilter')

        if filename is not None:
            self._reloadifnecessary()
        self.stripre = re.compile(r'<[^>]*?>')

    def _reloadifnecessary(self):
        now = time.time()
        # check if reloadinterval has passed
        if now - self.lastreload < self.reloadinterval:
            return
        if self.file_changed():
            self._reload()

    def _load_simplestyle_line(self, line):
        sp = line.split(None, 2)
        if len(sp) < 2:
            raise Exception(
                """"Invalid line '%s' in Rulefile %s. Ignoring.""" % (line, self.filename))

        args = None
        if len(sp) == 3:
            args = sp[2]

        fieldname = sp[0]
        # strip ending : (request AXB)
        if fieldname.endswith(':'):
            fieldname = fieldname[:-1]
        regex = sp[1]
        try:
            pattern = re.compile(regex, re.IGNORECASE | re.DOTALL)
        except Exception as e:
            raise Exception(
                'Could not compile regex %s in file %s (%s)' % (regex, self.filename, e))

        tup = (fieldname, pattern, args)
        return tup

    def _load_perlstyle_line(self, line):
        patt = r"""(?P<fieldname>[a-zA-Z0-9\-\.\_\:]+)[:]?\s+\/(?P<regex>(?:\\.|[^/\\])*)/(?P<flags>[IiMm]+)?((?:\s*$)|(?:\s+(?P<args>.*)))$"""
        m = re.match(patt, line)
        if m is None:
            return None

        groups = m.groupdict()
        regex = groups['regex']
        flags = groups['flags']
        if flags is None:
            flags = []
        args = groups['args']
        if args is not None and args.strip() == '':
            args = None
        fieldname = groups['fieldname']
        if fieldname.endswith(':'):
            fieldname = fieldname[:-1]

        reflags = 0
        for flag in flags:
            flag = flag.lower()
            if flag == 'i':
                reflags |= re.I
            if flag == 'm':
                reflags |= re.M

        try:
            pattern = re.compile(regex, reflags)
        except Exception as e:
            raise Exception(
                'Could not compile regex %s in file %s (%s)' % (regex, self.filename, e))

        tup = (fieldname, pattern, args)
        return tup

    def _reload(self):
        self.logger.info('Reloading Rulefile %s' % self.filename)
        statinfo = os.stat(self.filename)
        ctime = statinfo.st_ctime
        self.lastreload = ctime
        with open(self.filename, 'r') as fp:
            lines = fp.readlines()
        newpatterns = []

        for line in lines:
            line = line.strip()
            if line == "":
                continue
            if line.startswith('#'):
                continue

            # try advanced regex line
            #<headername> /regex/<flags> <arguments>
            try:
                tup = self._load_perlstyle_line(line)
                if tup is not None:
                    newpatterns.append(tup)
                    continue
            except Exception as e:
                self.logger.error(
                    "perl style line failed %s, error: %s" % (line, str(e)))
                continue

            # line shold be "headername    regex    arguments"
            try:
                tup = self._load_simplestyle_line(line)
                newpatterns.append(tup)
                continue
            except Exception as e:
                self.logger.error(str(e))
                continue

        self.patterns = newpatterns

    def strip_text(self, content, remove_tags=None, replace_nbsp=True, use_bfs=True):
        """Strip HTML Tags from content, replace newline with space (like Spamassassin)"""

        if remove_tags is None:
            remove_tags = ['script', 'style']

        # content may land as a bytes object in py3, so we have to convert to a string so we can
        # replace newline with space
        # if it's unicode, we don't convert
        if isinstance(content, bytes):  # in py2 bytes is an alias for str, no change
            content = str(content)
        content = content.replace("\n", " ")

        if HAVE_BEAUTIFULSOUP and use_bfs:
            if BS_VERSION >= 4:
                soup = BeautifulSoup.BeautifulSoup(content, "lxml")
            else:
                soup = BeautifulSoup.BeautifulSoup(content)
            for r in remove_tags:
                [x.extract() for x in soup.findAll(r)]

            if BS_VERSION >= 4:
                stripped = soup.get_text()
                if replace_nbsp:
                    stripped = stripped.replace(u'\xa0', u' ')
                return stripped
            else:
                stripped = ''.join(
                    # Can retain unicode check since BS < 4 is Py2 only
                    [e for e in soup.recursiveChildGenerator() \
                        if isinstance(e, unicode) \
                        and not isinstance(e, BeautifulSoup.Declaration) \
                        and not isinstance(e, BeautifulSoup.ProcessingInstruction) \
                        and not isinstance(e, BeautifulSoup.Comment)])
                if replace_nbsp:
                    stripped = stripped.replace(u'\xa0', u' ')
                return stripped

        # no BeautifulSoup available, let's try a modified version of pyzor's
        # html stripper
        stripper = HTMLStripper(strip_tags=remove_tags)
        
        try:
            # always try to replace nbsp as HTMLStripper would just remove them
            content = content.replace("&nbsp;", " ").replace("&#xa0;", " ").replace("&#160;", " ")
        except Exception:
            pass
        
        try:
            stripper.feed(content)
            return stripper.get_stripped_data()
        except Exception:  # ignore parsing/encoding errors
            pass
        # use regex replace
        return re.sub(self.stripre, '', content)

    def get_decoded_textparts(self, messagerep):
        """Returns a list of all text contents"""
        textparts = []
        for part in messagerep.walk():
            payload = None
            if part.get_content_maintype() == 'text' and (not part.is_multipart()):
                payload = part.get_payload(None, True)

            #multipart/mixed are text by default as well
            if part.get_content_maintype() == 'multipart' and part.get_content_subtype() == 'mixed':
                payload = part.get_payload(None, True)

            # payload can be None even if it was returned from part.get_payload()
            if payload is not None:
                textparts.append(payload)
        return textparts

    def get_field(self, suspect, headername):
        """return a list of mail header values or special values. If the value can not be found, an empty list is returned.

        headers:
            just the headername for normal headers
            mime:headername for attached mime part headers

        envelope data:
            envelope_from (or from_address)
            envelope_to (or to_address)
            from_domain
            to_domain
            clientip
            clienthostname (fcrdns or 'unknown')
            clienthelo

        tags
            @tagname

        body source:
            body:full -> (full source, encoded)
            body:stripped (or just 'body') : -> returns text/* bodyparts with tags and newlines stripped
            body:raw -> decoded raw message body parts


        """
        # builtins
        if headername == 'envelope_from' or headername == 'from_address':
            return [suspect.from_address, ]
        if headername == 'envelope_to' or headername == 'to_address':
            return suspect.recipients
        if headername == 'from_domain':
            return [suspect.from_domain, ]
        if headername == 'to_domain':
            return [suspect.to_domain, ]
        if headername == 'body:full':
            return [suspect.get_original_source()]

        if headername in ['clientip', 'clienthostname', 'clienthelo']:
            clinfo = suspect.get_client_info()
            if clinfo is None:
                return []
            if headername == 'clienthelo':
                return [clinfo[0], ]
            if headername == 'clientip':
                return [clinfo[1], ]
            if headername == 'clienthostname':
                return [clinfo[2], ]

        # if it starts with a @ we return a tag, not a header
        if headername[0:1] == '@':
            tagname = headername[1:]
            tagval = suspect.get_tag(tagname)
            if tagval is None:
                return []
            if isinstance(tagval, list):
                return tagval
            return [tagval]

        messagerep = suspect.get_message_rep()

        # body rules on decoded text parts
        if headername == 'body:raw':
            return self.get_decoded_textparts(messagerep)

        if headername == 'body' or headername == 'body:stripped':
            return list(map(self.strip_text, self.get_decoded_textparts(messagerep)))

        if headername.startswith('mime:'):
            allvalues = []
            realheadername = headername[5:]
            for part in messagerep.walk():
                hdrslist = self._get_headers(realheadername, part)
                allvalues.extend(hdrslist)
            return allvalues

        # standard header
        return self._get_headers(headername, messagerep)

    def _get_headers(self, headername, payload):
        valuelist = []
        if '*' in headername:
            regex = re.escape(headername)
            regex = regex.replace('\*', '.*')
            patt = re.compile(regex, re.IGNORECASE)

            for h in list(payload.keys()):
                if re.match(patt, h) is not None:
                    valuelist.extend(payload.get_all(h,[]))
        else:
            valuelist = payload.get_all(headername,[])

        return valuelist

    def matches(self, suspect, extended=False):
        """returns (True,arg) if any regex matches, (False,None) otherwise

        if extended=True, returns all available info about the match in a tuple:
        True, (fieldname, matchedvalue, arg, regex)
        """
        self._reloadifnecessary()

        for tup in self.patterns:
            (fieldname, pattern, arg) = tup
            vals = self.get_field(suspect, fieldname)
            if vals is None or len(vals) == 0:
                self.logger.debug('No field %s found' % fieldname)
                continue

            for val in vals:
                if val is None:
                    continue

                strval = str(val)
                if pattern.search(strval):
                    self.logger.debug("""MATCH field %s (arg '%s') regex '%s' against value '%s'""" % (
                        fieldname, arg, pattern.pattern, val))
                    suspect.debug("message matches rule in %s: field=%s arg=%s regex=%s content=%s" % (
                        self.filename, fieldname, arg, pattern.pattern, val))
                    if extended:
                        return True, (fieldname, strval, arg, pattern.pattern)
                    else:
                        return True, arg
                else:
                    self.logger.debug("""NO MATCH field %s (arg '%s') regex '%s' against value '%s'""" % (
                        fieldname, arg, pattern.pattern, val))

        self.logger.debug('No match found')
        suspect.debug("message does not match any rule in %s" % self.filename)
        return False, None

    def get_args(self, suspect, extended=False):
        """returns all args of matched regexes in a list
        if extended=True:  returns a list of tuples with all available information:
        (fieldname, matchedvalue, arg, regex)
        """
        ret = []
        self._reloadifnecessary()
        for tup in self.patterns:
            (fieldname, pattern, arg) = tup
            vals = self.get_field(suspect, fieldname)
            if vals is None or len(vals) == 0:
                self.logger.debug('No field %s found' % fieldname)
                continue
            for val in vals:
                if val is None:
                    continue
                strval = str(val)
                if pattern.search(strval) is not None:
                    self.logger.debug("""MATCH field %s (arg '%s') regex '%s' against value '%s'""" % (
                        fieldname, arg, pattern.pattern, val))
                    suspect.debug("message matches rule in %s: field=%s arg=%s regex=%s content=%s" % (
                        self.filename, fieldname, arg, pattern.pattern, val))
                    if extended:
                        ret.append((fieldname, strval, arg, pattern.pattern))
                    else:
                        ret.append(arg)
                else:
                    self.logger.debug("""NO MATCH field %s (arg '%s') regex '%s' against value '%s'""" % (
                        fieldname, arg, pattern.pattern, val))

        return ret

    def getArgs(self, suspect):
        """old name for get_args"""
        return self.get_args(suspect)

    def file_changed(self):
        """Return True if the file has changed on disks since the last reload"""
        if not os.path.isfile(self.filename):
            return False
        statinfo = os.stat(self.filename)
        ctime = statinfo.st_ctime
        if ctime > self.lastreload:
            return True
        return False

    def lint(self):
        """check file and print warnings to console. returns True if everything is ok, False otherwise"""
        if not os.path.isfile(self.filename):
            print("SuspectFilter file not found: %s" % self.filename)
            return False
        with open(self.filename, 'r') as fp:
            lines = fp.readlines()
        lineno = 0
        for line in lines:
            lineno += 1
            line = line.strip()
            if line == "":
                continue
            if line.startswith('#'):
                continue
            try:
                tup = self._load_perlstyle_line(line)
                if tup is not None:
                    continue
                self._load_simplestyle_line(line)
            except Exception as e:
                print("Error in SuspectFilter file '%s', lineno %s , line '%s' : %s" % (
                    self.filename, lineno, line, str(e)))
                return False
        return True


class HTMLStripper(HTMLParser):

    def __init__(self, strip_tags=None):
        HTMLParser.__init__(self)
        self.strip_tags = strip_tags or ['script', 'style']
        self.reset()
        self.collect = True
        self.stripped_data = []

    def handle_data(self, data):
        if data and self.collect:
            self.stripped_data.append(data)

    def handle_starttag(self, tag, attrs):
        HTMLParser.handle_starttag(self, tag, attrs)
        if tag.lower() in self.strip_tags:
            self.collect = False

    def handle_endtag(self, tag):
        HTMLParser.handle_endtag(self, tag)
        if tag.lower() in self.strip_tags:
            self.collect = True

    def get_stripped_data(self):
        return ''.join(self.stripped_data)


class FileList(object):

    """Map all lines from a textfile into a list. If the file is changed, the list is refreshed automatically
    Each line can be run through a callback filter which can change or remove the content.

    filename: The textfile which should be mapped to a list. This can be changed at runtime. If None, an empty list will be returned.
    strip: remove leading/trailing whitespace from each line. Note that the newline character is always stripped
    skip_empty: skip empty lines (if used in combination with strip: skip all lines with only whitespace)
    skip_comments: skip lines starting with #
    lowercase: lowercase each line
    additional_filters: function or list of functions which will be called for each line on reload.
        Each function accept a single argument and must return a (possibly modified) line or None to skip this line
    minimum_time_between_reloads: number of seconds to cache the list before it will be reloaded if the file changes
    """

    def __init__(self, filename=None, strip=True, skip_empty=True, skip_comments=True, lowercase=False, additional_filters=None, minimum_time_between_reloads=5):
        self.filename = filename
        self.minium_time_between_reloads = minimum_time_between_reloads
        self._lastreload = 0
        self.linefilters = []
        self.content = []
        self.logger = logging.getLogger('%s.filelist' % __package__)
        self.lock = threading.Lock()

        # we always strip newline
        self.linefilters.append(lambda x: x.rstrip('\r\n'))

        if strip:
            self.linefilters.append(lambda x: x.strip())

        if skip_empty:
            self.linefilters.append(lambda x: x if x != '' else None)

        if skip_comments:
            self.linefilters.append(
                lambda x: None if x.strip().startswith('#') else x)

        if lowercase:
            self.linefilters.append(lambda x: x.lower())

        if additional_filters is not None:
            if isinstance(additional_filters, list):
                self.linefilters.extend(additional_filters)
            else:
                self.linefilters.append(additional_filters)

        if filename is not None:
            self._reload_if_necessary()

    def _reload_if_necessary(self):
        """Calls _reload if the file has been changed since the last reload"""
        now = time.time()
        # check if reloadinterval has passed
        if now - self._lastreload < self.minium_time_between_reloads:
            return
        if not self.file_changed():
            return
        if not self.lock.acquire():
            return
        try:
            self._reload()
        finally:
            self.lock.release()

    def _reload(self):
        """Reload the file and build the list"""
        self.logger.info('Reloading file %s' % self.filename)
        statinfo = os.stat(self.filename)
        ctime = statinfo.st_ctime
        self._lastreload = ctime
        with open(self.filename, 'r') as fp:
            lines = fp.readlines()
        newcontent = []

        for line in lines:
            for func in self.linefilters:
                line = func(line)
                if line is None:
                    break

            if line is not None:
                newcontent.append(line)

        self.content = newcontent

    def file_changed(self):
        """Return True if the file has changed on disks since the last reload"""
        if not os.path.isfile(self.filename):
            return False
        statinfo = os.stat(self.filename)
        ctime = statinfo.st_ctime
        if ctime > self._lastreload:
            return True
        return False

    def get_list(self):
        """Returns the current list. If the file has been changed since the last call, it will rebuild the list automatically."""
        self._reload_if_necessary()
        return self.content



class Cache(object):
    """
    Simple local cache object.
    cached data will expire after a defined interval
    """
    
    def __init__(self, cachetime=30, cleanupinterval=300):
        self.cache={}
        self.cachetime=cachetime
        self.cleanupinterval=cleanupinterval
        self.lock=threading.Lock()
        self.logger=logging.getLogger("%s.settingscache" % __package__)
        
        t = threading.Thread(target=self.clear_cache_thread)
        t.daemon = True
        t.start()
    
    
    def put_cache(self,key,obj):
        try:
            gotlock=self.lock.acquire(True)
            if gotlock:
                self.cache[key]=(obj,time.time())
        except Exception as e:
            self.logger.exception(e)
        finally:
            if gotlock:
                self.lock.release()
    
    
    def get_cache(self,key):
        try:
            gotlock=self.lock.acquire(True)
            if not gotlock:
                return None
        
            ret=None

            if key in self.cache:
                obj,instime=self.cache[key]
                now=time.time()
                if now-instime<self.cachetime:
                    ret=obj
                else:
                    del self.cache[key]

        except Exception as e:
            self.logger.exception(e)
        finally:
            self.lock.release()
        return ret
    
    
    def clear_cache_thread(self):
        while True:
            time.sleep(self.cleanupinterval)
            now=time.time()
            try:
                gotlock=self.lock.acquire(True)
                if not gotlock:
                    continue

                cleancount=0

                for key in set(self.cache.keys()):
                    obj,instime=self.cache[key]
                    if now-instime>self.cachetime:
                        del self.cache[key]
                        cleancount+=1
            except Exception as e:
                self.logger.exception(e)
            finally:
                if gotlock:
                    self.lock.release()
            self.logger.debug("Cleaned %s expired entries."%cleancount)



class CacheSingleton(object):
    """
    Process singleton to store a default Cache instance
    Note it is important there is a separate Cache instance for each process
    since otherwise the Threading.Lock will screw up and block the execution.
    """

    instance = None
    procPID = None

    def __init__(self, *args, **kwargs):
        pid =  os.getpid()
        logger = logging.getLogger("%s.CacheSingleton" % __package__)
        if pid == CacheSingleton.procPID and CacheSingleton.instance is not None:
            logger.debug("Return existing Cache Singleton for process with pid: %u"%pid)
        else:
            if CacheSingleton.instance is None:
                logger.info("Create CacheSingleton for process with pid: %u"%pid)
            elif CacheSingleton.procPID != pid:
                logger.warning("Replace CacheSingleton(created by process %u) for process with pid: %u"%(CacheSingleton.procPID,pid))

            CacheSingleton.instance = Cache(*args,**kwargs)
            CacheSingleton.procPID  = pid

    def __getattr__(self, name):
        return getattr(self.instance, name)


def get_default_cache():
    """
    Function to get processor unique Cache Singleton
    """
    return CacheSingleton()
