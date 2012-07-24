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
import logging
import os
import time
import socket

_HASHLIB=0
_MD5=1

MD5LIB=-1
try:
    import hashlib
    MD5LIB=_HASHLIB
except:
    MD5LIB=_MD5
    import md5
    
    
HAVE_BEAUTIFULSOUP=False
try:
    import BeautifulSoup
    HAVE_BEAUTIFULSOUP=True
except:
    pass

import random
import email
import re
import unittest
import ConfigParser
import datetime
from string import Template
from email.Header import Header
#constants

DUNNO=0 #go on
ACCEPT=1 # accept message, no further tests
DELETE=2 # blackhole, no further tests
REJECT=3 # reject, no further tests
DEFER=4 # defer, no further tests

ALLCODES={
          'DUNNO':DUNNO,
          'ACCEPT':ACCEPT,
          'DELETE':DELETE,
          'REJECT':REJECT,
          'DEFER':DEFER,
          }

def actioncode_to_string(actioncode):
    """Return the human readable string for this code"""
    for key,val in ALLCODES.items():
        if val==actioncode:
            return key
    if actioncode==None:
        return "NULL ACTION CODE"
    return 'INVALID ACTION CODE %s'%actioncode

def string_to_actioncode(actionstring,config=None):
    """return the code for this action"""
    upper=actionstring.upper().strip()
    if config!=None:
        if upper=='DEFAULTHIGHSPAMACTION':
            confval=config.get('spam','defaulthighspamaction').upper()
            if not ALLCODES.has_key(confval):
                return None
            return ALLCODES[confval]
       
        if upper=='DEFAULTLOWSPAMACTION':
            confval=config.get('spam','defaultlowspamaction').upper()
            if not ALLCODES.has_key(confval):
                return None
            return ALLCODES[confval]
       
        if upper=='DEFAULTVIRUSACTION':
            confval=config.get('virus','defaultvirusaction').upper()
            if not ALLCODES.has_key(confval):
                return None
            return ALLCODES[confval]
           
    if not ALLCODES.has_key(upper):
        return None
    return ALLCODES[upper]


def apply_template(templatecontent,suspect,values=None):
    if values==None:
        values={}

    values['id']=suspect.id
    values['timestamp']=suspect.timestamp
    values['from_address']=suspect.from_address
    values['to_address']=suspect.to_address
    values['from_domain']=suspect.from_domain
    values['to_domain']=suspect.to_domain
    values['subject']=suspect.getMessageRep()['subject']
    values['date']=str(datetime.date.today())
    values['time']=time.strftime('%X')
    
    template = Template(templatecontent)
    
    message= template.safe_substitute(values)
    return message


HOSTNAME=socket.gethostname()

class Suspect(object):
    """
    The suspect represents the message to be scanned. Each scannerplugin will be presented
    with a suspect and may modify the tags or even the message content itself.
    """
    
    def __init__(self,from_address,to_address,tempfile):        
        self.source = None
        """holds the message source if set directly"""
        
        #tags set by plugins
        self.tags={}
        self.tags['virus']={}
        self.tags['spam']={}
        self.tags['highspam']={}
        self.tags['decisions']=[]
        
        
        #temporary file containing the message source
        self.tempfile=tempfile
 
        #stuff set from smtp transaction
        self.size=os.path.getsize(tempfile)
        self.from_address=from_address
        self.to_address=to_address  # for plugins supporting only one recipient
        self.recipients=[] # for plugins supporting multiple recipients
        
        #additional basic information
        self.timestamp=time.time()
        self.id=self._generate_id()
        
        #headers 
        self.addheaders={}
        self.replaceheaders={}
        
        #helper attributes
        if self.from_address==None:
            self.from_address=''
            
        try:
            (user, self.to_domain) = self.to_address.rsplit('@',1)
        except:
            raise ValueError,"invalid to email address: %s"%self.to_address
      
        
        if self.from_address=='':
            self.from_domain=''
        else:
            try:
                (user, self.from_domain) = self.from_address.rsplit('@',1)
            except Exception, e:
                raise ValueError,"invalid from email address: '%s'"%self.from_address
    
    def _generate_id(self):
        """
        generate a new id for a message. 
        uses hash of hostname+current time+random int which 
        should be sufficiently unique for the quarantine
        """
        uni="%s%s%s"%(HOSTNAME,time.time(),random.randint(1,10000))
        id=None
        if MD5LIB==_HASHLIB:
            id=hashlib.md5(uni).hexdigest()
        else:
            id=md5.new(uni).hexdigest()
        return id
    
    
    def debug(self,message):
        """Add a line to the debug log if debugging is enabled for this message"""
        if not self.get_tag('debug'):
            return
        isotime=datetime.datetime.now().isoformat()
        fp=self.get_tag('debugfile')
        try:
            fp.write('%s %s\n'%(isotime,message))
            fp.flush()
        except Exception,e:
            logging.getLogger('suspect').error('Could not write to logfile: %s'%e)
            
        
          
    def get_tag(self,key):
        """returns the tag value"""
        if not self.tags.has_key(key):
            return None
        return self.tags[key]
    
    def set_tag(self,key,value):
        """Set a new tag"""
        self.tags[key]=value
        
    def is_highspam(self):
        """Returns True if ANY of the spam engines tagged this suspect as high spam"""
        for key in self.tags['highspam'].keys():
            val=self.tags['highspam'][key]
            if val:
                return True
        return False
    
    def is_spam(self):
        """Returns True if ANY of the spam engines tagged this suspect as spam"""
        for key in self.tags['spam'].keys():
            val=self.tags['spam'][key]
            if val:
                return True
        return False
    
    
    def add_header(self,key,value,immediate=False):
        """adds a header to the message. by default, headers will added when re-injecting the message back to postfix
        if you set immediate=True the message source will be replaced immediately. Only set this to true if a header must be
        visible to later plugins (eg. for spamassassin rules), otherwise, leave as False which is faster.
        """
        if immediate:
            val=unicode(value,errors='ignore')  # is ignore the right thing to do here?
            hdr=Header(val, header_name=key, continuation_ws=' ')
            hdrline="%s: %s\n"%(key,hdr.encode())
            src=hdrline+self.getSource()
            self.setSource(src)
        else:
            self.addheaders[key]=value
        
    def addheader(self,key,value,immediate=False):
        """old name for add_header"""
        return self.add_header(key, value, immediate)
    
    def is_virus(self):
        """Returns True if ANY of the antivirus engines tagged this suspect as infected"""
        for key in self.tags['virus'].keys():
            val=self.tags['virus'][key]
            if val:
                return True
        return False
    
    def __str__(self):
        """representation good for logging"""
        virusstring="no"
        if self.is_virus():
            virusstring="yes"
        spamstring="no"
        if self.is_spam():
            spamstring="yes"
        
        modifiedstring="no"
        if self.is_modified():
            modifiedstring="yes"
        
        
        blacklist=['decisions',]
        tagscopy={}
        
        for k,v in self.tags.iteritems():
            if k in blacklist:
                continue
            
            try:
                strrep=str(v)
            except: #Unicodedecode errors and stuff like that
                continue
            
            therep=v
            
            maxtaglen=100
            if len(strrep)>maxtaglen:
                therep=strrep[:maxtaglen]+"..."
            
            #specialfixes
            if k=='SAPlugin.spamscore':
                therep="%.2f"%v
            
            tagscopy[k]=therep
                
        astring="Suspect %s: from=%s to=%s size=%s spam=%s virus=%s modified=%s tags=%s"%(self.id,self.from_address, self.to_address,self.size,spamstring,virusstring,modifiedstring,tagscopy)
        return astring
    
    def get_message_rep(self):
        """returns the python email api representation of this suspect"""
        if self.source!=None:
            return email.message_from_string(self.source)
        else:
            fh=open(self.tempfile,'r')
            msgrep=email.message_from_file(fh)
            fh.close()
            return msgrep
    
    def getMessageRep(self):
        """old name for get_message_rep"""
        return self.get_message_rep()
    
    def set_message_rep(self,msgrep):
        """replace the message content. this must be a standard python email representation
        Warning: setting the source via python email representation seems to break dkim signatures!
        """
        self.setSource(msgrep.as_string())
    
    def setMessageRep(self,msgrep):
        """old name for set_message_rep"""
        return self.set_message_rep(msgrep)
    
        
    def is_modified(self):
        """returns true if the message source has been modified"""
        return self.source!=None
    
    def get_source(self,maxbytes=None):
        """returns the current message source, possibly changed by plugins"""
        if self.source!=None:
            return self.source[:maxbytes]
        else:
            return self.get_original_source(maxbytes)
        
    def getSource(self,maxbytes=None):
        """old name for get_source"""
        return self.get_source(maxbytes)
        
    def set_source(self,source):
        self.source=source
    
    def setSource(self,source):
        """old name for set_source"""
        return self.set_source(source)
     
    def get_original_source(self,maxbytes=None):
        """returns the original, unmodified message source"""
        readbytes=-1
        if maxbytes!=None:
            readbytes=maxbytes
        try:
            source=open(self.tempfile).read(readbytes)
        except Exception,e:
            logging.getLogger('fuglu.suspect').error('Cannot retrieve original source from tempfile %s : %s'%(self.tempfile,str(e)))
            raise e
        return source
    
    def getOriginalSource(self,maxbytes=None):
        """old name for get_original_source"""
        return self.get_original_source(maxbytes)

    def get_headers(self):
        """returns the message headers as string"""
        headers=re.split('(?:\n\n)|(?:\r\n\r\n)',self.getSource(maxbytes=1048576),1)[0]
        return headers
        
##it is important that this class explicitly extends from object, or __subclasses__() will not work!
class BasicPlugin(object):
    """Base class for all plugins"""
    
    def __init__(self,config,section=None):
        if section==None:
            self.section=self.__class__.__name__
        else:
            self.section=section
            
        self.config=config
        self.requiredvars={}
    
    def _logger(self):
        """returns the logger for this plugin"""
        myclass=self.__class__.__name__
        loggername="fuglu.plugin.%s"%(myclass)
        return logging.getLogger(loggername)
    
    def lint(self):
        return self.checkConfig()
    
    def checkConfig(self):
        allOK=True
        
        #old config style
        if type(self.requiredvars)==tuple or type(self.requiredvars)==list:
            for configvar in self.requiredvars:
                if type(self.requiredvars)==tuple:
                    (section,config)=configvar
                else:
                    config=configvar
                    section=self.section                   
                try:
                    var=self.config.get(section,config)
                except ConfigParser.NoOptionError:
                    print "Missing configuration value [%s] :: %s"%(section,config)
                    allOK=False
                except ConfigParser.NoSectionError:
                    print "Missing configuration section %s"%(section)
                    allOK=False    
        
        #new config style
        if type(self.requiredvars)==dict:
            for config,infodic in self.requiredvars.iteritems():
                section=self.section
                if 'section' in infodic:
                    section=infodic['section']
                    
                try:
                    var=self.config.get(section,config)
                    if 'validator' in infodic:
                        if not infodic["validator"](var):
                            print "Validation failed for [%s] :: %s"%(section,config)
                            allOK=False          
                except ConfigParser.NoSectionError:
                    print "Missing configuration section [%s] :: %s"%(section,config)
                    allOK=False
                except ConfigParser.NoOptionError:
                    print "Missing configuration value [%s] :: %s"%(section,config)
                    allOK=False
        
        return allOK

    def __str__(self):
        classname=self.__class__.__name__
        if self.section==classname:
            return classname;
        else:
            return '%s(%s)'%(classname,self.section)

class ScannerPlugin(BasicPlugin):
    """Scanner Plugin Base Class"""
    def examine(self,suspect):
        self._logger().warning('Unimplemented examine() method')

class PrependerPlugin(BasicPlugin):
    """Prepender Plugins - Plugins run before the scanners that can influence
    the list of scanners being run for a certain message"""
    
    def pluginlist(self,suspect,pluginlist):
        """return the modified pluginlist or None for no change"""
        self._logger().warning('Unimplemented pluginlist() method')
        return None
        
class AppenderPlugin(BasicPlugin):
    """Appender Plugins are run after the scan process (and after the re-injection if the message
    was accepted)"""
    def process(self,suspect,decision):
        self._logger().warning('Unimplemented process() method')


class SuspectFilter(object):
    """Allows filtering Suspect based on header/tag/body regexes"""
    def __init__(self,filename):
        self.filename=filename
        self.patterns=[]
        
        self.reloadinterval=30
        self.lastreload=0
        self.logger=logging.getLogger('fuglu.suspectfilter')
        self._reloadifnecessary()
        self.recache={}
        self.stripre=re.compile(r'<[^>]*?>')
        
    def _reloadifnecessary(self):
        now=time.time()
        #check if reloadinterval has passed
        if now-self.lastreload<self.reloadinterval:
            return
        if self.filechanged():
            self._reload()
    
    
    def _load_simplestyle_line(self,line):
        sp=line.split(None,2)
        if len(sp)<2:
            raise Exception(""""Invalid line '%s' in Rulefile %s. Ignoring."""%(line,self.filename))
        
        args=None
        if len(sp)==3:
            args=sp[2]
            
        fieldname=sp[0]
        #strip ending : (request AXB)
        if fieldname.endswith(':'):
            fieldname=fieldname[:-1]
        regex=sp[1]
        try:
            pattern=re.compile(regex, re.IGNORECASE|re.DOTALL)
        except Exception,e:
            raise Exception('Could not compile regex %s in file %s (%s)'%(regex,self.filename,e))
        
        tup=(fieldname,pattern,args)
        return tup
    
    def _load_perlstyle_line(self,line):
        patt=r"""(?P<fieldname>[a-zA-Z0-9\-\.\_\:]+)[:]?\s+\/(?P<regex>(?:\\.|[^/\\])*)/(?P<flags>[IiMm]+)?((?:\s*$)|(?:\s+(?P<args>.*)))$"""
        m=re.match(patt,line)
        if m==None:
            return None
        
        groups=m.groupdict()
        regex=groups['regex']
        flags=groups['flags']
        if flags==None:
            flags=[]
        args=groups['args']
        if args!=None and args.strip()=='':
            args=None
        fieldname=groups['fieldname']
        if fieldname.endswith(':'):
            fieldname=fieldname[:-1]
            
        reflags=0
        for flag in flags:
            flag=flag.lower()
            if flag=='i':
                reflags|=re.I
            if flag=='m':
                reflags|=re.M
            
        try:
            pattern=re.compile(regex, reflags)
        except Exception,e:
            raise Exception('Could not compile regex %s in file %s (%s)'%(regex,self.filename,e))
        
        tup=(fieldname,pattern,args)
        return tup
        
    
    def _reload(self):
        self.logger.info('Reloading Rulefile %s'%self.filename)
        statinfo=os.stat(self.filename)
        ctime=statinfo.st_ctime
        self.lastreload=ctime
        fp=open(self.filename,'r')
        lines=fp.readlines()
        fp.close()
        newpatterns=[]
        
        for line in lines:
            line=line.strip()
            if line=="":
                continue
            if line.startswith('#'):
                continue
            
            
            #try advanced regex line
            #<headername> /regex/<flags> <arguments>
            try:
                tup=self._load_perlstyle_line(line)
                if tup!=None:
                    newpatterns.append(tup)
                    continue
            except Exception,e:
                self.logger.error("perl style line failed %s, error: %s"%(line,str(e)))
                continue
            
            
            #line shold be "headername    regex    arguments"
            try:
                tup=self._load_simplestyle_line(line)
                newpatterns.append(tup)
                continue
            except Exception,e:
                self.logger.error(str(e))
                continue
            
        self.patterns=newpatterns
    
    
    def strip_text(self,content):
        """Strip HTML Tags from content, replace newline with space (like Spamassassin)"""
        
        #replace newline with space
        content=content.replace("\n", " ")
        
        if HAVE_BEAUTIFULSOUP:
            soup = BeautifulSoup.BeautifulSoup(content)
            stripped=''.join([e for e in soup.recursiveChildGenerator() if isinstance(e,unicode)])
            return stripped

        #no library available, use regex replace
        return re.sub(self.stripre, '', content)
    
    def get_decoded_textparts(self,messagerep):
        """Returns a list of all text contents"""
        textparts=[]
        for part in messagerep.walk():
            if part.get_content_maintype()=='text' and (not part.is_multipart()):
                textparts.append(part.get_payload(None,True))
        return textparts
    
    def _getField(self,suspect,headername,messagerep=None):
        """return mail header value or special value. msgrep should be the cached suspects messagerep
        so we don't have to load it for every call to _getField
        """         
        #builtins
        if headername=='envelope_from' or headername=='from_address':
            return [suspect.from_address,]
        if headername=='envelope_to' or headername=='to_address':
            return suspect.recipients
        if headername=='from_domain':
            return [suspect.from_domain,]
        if headername=='to_domain':
            return [suspect.to_domain,]
        if headername=='body:full':
            return [suspect.getOriginalSource()]
        
        #if it starts with a @ we return a tag, not a header
        if headername[0:1]=='@':
            tagname=headername[1:]
            tagval=suspect.get_tag(tagname)
            if tagval==None:
                compareval=''
            else:
                compareval=str(tagval)
            return [compareval,]
        
        if messagerep==None:
            messagerep=suspect.getMessageRep()
        
        #body rules on decoded text parts
        if headername=='body:raw':
            return self.get_decoded_textparts(messagerep)
        
        if headername=='body' or headername=='body:stripped':
            return map(self.strip_text, self.get_decoded_textparts(messagerep))
        
        if headername.startswith('mime:'):
            allvalues=[]
            realheadername=headername[5:]
            for part in messagerep.walk():
                hdrslist=self._get_headers(realheadername, part)
                if hdrslist!=None:
                    allvalues.extend(hdrslist)
            return allvalues
                
        #standard header
        return self._get_headers(headername, messagerep)
    
    def _get_headers(self,headername,payload):
        valuelist=[]
        if '*' in headername:
            regex=re.escape(headername)
            regex=regex.replace('\*','.*')
            if regex in self.recache:
                patt=self.recache[regex]
            else:
                patt=re.compile(regex,re.IGNORECASE)
                self.recache[regex]=patt
            
            for h in payload.keys():
                if re.match(patt, h)!=None:
                    valuelist.extend(payload.get_all(h))
        else:
            valuelist=payload.get_all(headername)
            
        return valuelist
           
           
    def matches(self,suspect):
        """returns (True,arg) if any regex matches, (False,None) otherwise"""
        self._reloadifnecessary()
        messagerep=suspect.getMessageRep()
        
        for tup in self.patterns:
            (headername,pattern,arg)=tup
            vals=self._getField(suspect,headername,messagerep=messagerep)
            if vals==None:
                self.logger.debug('No header %s found'%headername)
                continue
            
            for val in vals:
                if val==None:
                    continue
                #self.logger.debug("""Checking headername %s (arg '%s') regex '%s' against value %s"""%(headername,arg,pattern.pattern,val))
                if pattern.search(str(val)):   
                    self.logger.debug("""MATCH field %s (arg '%s') regex '%s' against value '%s'"""%(headername,arg,pattern.pattern,val))
                    return (True,arg)
                else:
                    self.logger.debug("""NO MATCH field %s (arg '%s') regex '%s' against value '%s'"""%(headername,arg,pattern.pattern,val))
                    
        self.logger.debug('No match found')
        return (False,None)
    
    def get_args(self,suspect):
        """returns all args of matched regexes in a list"""
        ret=[]
        self._reloadifnecessary()
        for tup in self.patterns:
            (headername,pattern,arg)=tup
            vals=self._getField(suspect,headername)
            if vals==None:
                self.logger.debug('No field %s found'%headername)
                continue
            for val in vals:
                if val==None:
                    continue
                if pattern.search(str(val))!=None:
                    self.logger.debug("""MATCH field %s (arg '%s') regex '%s' against value '%s'"""%(headername,arg,pattern.pattern,val))
                    ret.append (arg)
                else:
                    self.logger.debug("""NO MATCH field %s (arg '%s') regex '%s' against value '%s'"""%(headername,arg,pattern.pattern,val))
                    
        return ret
    
    
    def getArgs(self,suspect):
        """old name for get_args"""
        return self.get_args(suspect)
    
    def filechanged(self):
        statinfo=os.stat(self.filename)
        ctime=statinfo.st_ctime
        if ctime>self.lastreload:
            return True
        return False
    
    
  
class SuspectFilterTestCase(unittest.TestCase):
    """Test Header Filter"""
    def setUp(self):     
        self.candidate=SuspectFilter('testdata/headertest.regex')
 
    def tearDown(self):
        pass     

    def test_hf(self):
        """Test header filters"""

        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org','testdata/helloworld.eml')
        suspect.tags['testtag']='testvalue'
        
        headermatches= self.candidate.getArgs(suspect)
        self.failUnless('Sent to unittest domain!' in headermatches, "To_domain not found in headercheck")
        self.failUnless('Envelope sender is sender@unittests.fuglu.org' in headermatches,"Envelope Sender not matched in header chekc")
        self.failUnless('Mime Version is 1.0' in headermatches,"Standard header Mime Version not found")
        self.failUnless('A tag match' in headermatches,"Tag match did not work")
        self.failUnless('Globbing works' in headermatches,"header globbing failed")
        self.failUnless('body rule works' in headermatches,"decoded body rule failed")
        self.failUnless('full body rule works' in headermatches,"full body failed")
        self.failUnless('mime rule works' in headermatches,"mime rule failed")
        self.failIf('this should not match in a body rule' in headermatches,'decoded body rule matched raw body')
        
        #perl style advanced rules
        self.failUnless('perl-style /-notation works!' in headermatches,"new rule format failed: %s"%headermatches)
        self.failUnless('perl-style recipient match' in headermatches,"new rule format failed for to_domain: %s"%headermatches)
        self.failIf('this should not match' in headermatches,"rule flag ignorecase was not detected")
        
        #TODO: raw body rules
        (match,arg)=self.candidate.matches(suspect)
        self.failUnless(match,'Match should return True')

class ActionCodeTestCase(unittest.TestCase):
    def test_defaultcodes(self):
        """test actioncode<->string conversion"""
        conf=ConfigParser.ConfigParser()
        conf.add_section('spam')
        conf.add_section('virus')
        conf.set('spam', 'defaultlowspamaction', 'REJEcT')
        conf.set('spam','defaulthighspamaction','REjECT')
        conf.set('virus','defaultvirusaction','rejeCt')
        self.assertEqual(string_to_actioncode('defaultlowspamaction', conf),REJECT)
        self.assertEqual(string_to_actioncode('defaulthighspamaction', conf),REJECT)
        self.assertEqual(string_to_actioncode('defaultvirusaction', conf),REJECT)
        self.assertEqual(string_to_actioncode('nonexistingstuff'), None)
        self.assertEqual(actioncode_to_string(REJECT),'REJECT')


class TemplateTestcase(unittest.TestCase):
    """Test Templates"""
    def setUp(self):     
        pass
 
    def tearDown(self):
        pass     

    def test_template(self):
        """Test Basic Template function"""

        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org','testdata/helloworld.eml')
        suspect.tags['nobounce']=True
        
        reason="a three-headed monkey stole it"
        
        template="""Your message '${subject}' from ${from_address} to ${to_address} could not be delivered because ${reason}"""
        
        result=apply_template(template, suspect, dict(reason=reason))
        expected="""Your message 'Hello world!' from sender@unittests.fuglu.org to recipient@unittests.fuglu.org could not be delivered because a three-headed monkey stole it"""
        self.assertEquals(result,expected),"Got unexpected template result: %s"%result       
        