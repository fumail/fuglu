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
import sys
from fuglu.shared import ScannerPlugin,DELETE,DUNNO,Suspect
from fuglu.bounce import Bounce
#TODO import above doesn't work
import time
import re
import mimetypes
import os
import os.path
import logging
import unittest

from threading import Lock

MAGIC_AVAILABLE=False
try:
    import magic
    MAGIC_AVAILABLE=True
except ImportError:
    pass
    

FUATT_NAMESCONFENDING="-filenames.conf"
FUATT_CTYPESCONFENDING="-filetypes.conf"


class RulesCache( object ):
   """caches rule files and compiled regex patterns"""
    
   __shared_state = {}
   
   def __init__(self,rulesdir):
       self.__dict__ = self.__shared_state
       if not hasattr(self, 'rules'):
           self.rules={}
       if not hasattr(self,'regexcache'):
           self.regexcache={}
           
       if not hasattr(self, 'lock'):
           self.lock=Lock()
       if not hasattr(self,'logger'):
           self.logger=logging.getLogger('fuglu.plugin.FiletypePlugin.RulesCache')
       if not hasattr(self,'lastreload'):
           self.lastreload=0
       self.rulesdir=rulesdir
       self.reloadifnecessary()
       
       
   
   
   def getRegex(self,regex):
       """compile regex and return cached object"""
       if self.regexcache.has_key(regex):
           return self.regexcache[regex]
       try:
           prog=re.compile(regex, re.IGNORECASE)
       except Exception,e:
           self.logger.error('Regex compilation error for %s : %s'%(regex,e))
       self.regexcache[regex]=prog
       return prog
   
   def getRules(self,type,key):
       self.logger.debug('Rule cache request: [%s] [%s]'%(type,key))
       if not self.rules.has_key(type):
           self.logger.error('Invalid rule type requested: %s'%type)
       if not self.rules[type].has_key(key):
           self.logger.debug('Ruleset not found : [%s] [%s]'%(type,key))
           return None
       self.logger.debug('Ruleset found : [%s] [%s] '%(type,key))
       
       ret=self.rules[type][key]
       return ret
   
   def getCTYPERules(self,key):
       return self.getRules('ctype', key)
      
   def getNAMERules(self,key):
       return self.getRules('name', key)
       
   def reloadifnecessary(self):
       """reload rules if file changed"""
       if not self.rulesdirchanged():
           return
       if not self.lock.acquire():
               return
       try:
           self._loadrules()
       finally:
           self.lock.release()
   
   def rulesdirchanged(self):
       statinfo=os.stat(self.rulesdir)
       ctime=statinfo.st_ctime
       if ctime>self.lastreload:
           return True
       return False

   def _loadrules(self):
       """effectively loads the rules, do not call directly, only through reloadifnecessary"""
       self.logger.debug('Re-Loading attachment rules...')
       
       #set last timestamp
       statinfo=os.stat(self.rulesdir)
       ctime=statinfo.st_ctime
       self.lastreload=ctime
       
       
       filelist=os.listdir(self.rulesdir)
       
       newruleset={'name':{},'ctype':{}}
       
       rulecounter=0
       for filename in filelist:
           if  not (filename.endswith(FUATT_NAMESCONFENDING) or filename.endswith(FUATT_CTYPESCONFENDING)):
               self.logger.debug('Ignoring file %s'%filename)
               continue
           
           
           ruleset=self._loadonefile("%s/%s"%(self.rulesdir,filename))
           if ruleset==None:
               continue
           rulesloaded=len(ruleset)
           self.logger.debug('%s rules loaded from file %s'%(rulesloaded,filename))
           type='name'
           key=filename[0:-len(FUATT_NAMESCONFENDING)]
           if(filename.endswith(FUATT_CTYPESCONFENDING)):
              type='ctype'
              key=filename[0:-len(FUATT_CTYPESCONFENDING)]
           newruleset[type][key]=ruleset
           self.logger.debug('Updating cache: [%s][%s]'%(type,key))
           rulecounter+=rulesloaded
       
       totalfiles=len(filelist)
       self.rules=newruleset
       self.logger.info('Loaded %s rules from %s files'%(rulecounter,totalfiles))

   
   def _loadonefile(self,filename):
        """returns all rules in a file"""
        if not os.path.exists(filename):
            self.logger.error('Rules File %s does not exist'%filename)
            return None
        if not os.path.isfile(filename):
            self.logger.warning('Ignoring file %s - not a file'%filename)
            return None
        ret={}
        handle=open(filename)
        for line in handle.readlines():
            line=line.strip()
            if line.startswith('#') or line=='':
                continue
            tuple=line.split(None,2)
            if (len(tuple)!=3):
                self.logger.debug('Ignoring invalid line in %s (length %s): %s'%(filename,len(tuple),line))
            (action,regex,description)=tuple
            action=action.lower()
            if action!="allow" and action!="deny" and action!="delete":
                self.logger.error('Invalid rule action: %s'%action)
                continue
            
            tp=(action,regex,description)
            ret[regex]=tp
        return ret

class FiletypePlugin(ScannerPlugin):
    """Copy this to make a new plugin"""
    def __init__(self,config):
        ScannerPlugin.__init__(self,config)
        self.requiredvars=(('FiletypePlugin','template_blockedfile'),('FiletypePlugin','rulesdir'))
        self.logger=self._logger()
        if MAGIC_AVAILABLE:
            self.ms = magic.open(magic.MAGIC_MIME)
            self.ms.load()
        else:
            self.logger.warning('python-magic not available')
        self.rulescache=RulesCache(self.config.get('FiletypePlugin','rulesdir'))
        self.extremeverbosity=False
    
 
    def examine(self,suspect):  
        starttime=time.time()
        self.blockedfiletemplate=self.config.get('FiletypePlugin','template_blockedfile')
        
        returnaction=self.walk(suspect)
        

        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['FiletypePlugin.time']="%.4f"%difftime
        return returnaction
    
    def getFiletype(self,path):
        type =  self.ms.file(path)
        return type
    
    def getBuffertype(self,buffer):
        type=self.ms.buffer(buffer)
        return type
    

    def matchRules(self,ruleset,object,suspect):
        if ruleset==None:
            return DUNNO
        
        for regex in ruleset.keys():
                prog=self.rulescache.getRegex(regex)
                if self.extremeverbosity:
                    self._logger().debug('Attachment %s Rule %s'%(object,regex))
                if prog.search( object):
                    info=ruleset[regex]
                    action=info[0]
                    description=info[2]
                    self._logger().debug('Rulematch: Attachment=%s Rule=%s Description=%s Action=%s'%(object,regex,description,action))
                    suspect.debug('Rulematch: Attachment=%s Rule=%s Description=%s Action=%s'%(object,regex,description,action))
                    if action=='deny':
                        # remove non ascii chars
                        asciirep="".join([x for x in object if ord(x) < 128])
                        self._logger().info('Mail contains blocked attachment name/type %s (delete, send bounce) '%object)
                        blockinfo="%s: %s"%(asciirep,description)
                        suspect.tags['FiletypePlugin.errormessage']=blockinfo
                        bounce=Bounce(self.config)
                        bounce.send_raw_template(suspect.from_address, self.blockedfiletemplate, suspect,dict(blockinfo=blockinfo))
                        return DELETE
                    
                    if action=='delete':
                        self._logger().info('Mail contains blocked attachment name/type %s (delete, no bounce)'%object)
                        return DELETE
                    
                    if action=='accept':
                        return 'accept'
        return DUNNO


    def matchMultipleSets(self,setlist,object,suspect):
        """run through multiple sets and return the first action which matches object"""
        self._logger().debug('Checking Object %s against attachment rulesets'%object)
        for ruleset in setlist:
            res=self.matchRules(ruleset, object,suspect)
            if res!=DUNNO:
                return res
        return DUNNO
    
    def walk(self,suspect):
        """walks through a message and checks each attachment according to the rulefile specified in the config"""
        self.rulescache.reloadifnecessary()
        user_names=self.rulescache.getNAMERules(suspect.to_address)
        
        
        user_ctypes=self.rulescache.getCTYPERules(suspect.to_address)
        
        domain_names=self.rulescache.getNAMERules(suspect.to_domain)
        domain_ctypes=self.rulescache.getCTYPERules(suspect.to_domain)
        
        default_names=self.rulescache.getNAMERules('default')
        default_ctypes=self.rulescache.getCTYPERules('default')
        
        m=suspect.getMessageRep()
        for i in m.walk():
            if i.is_multipart():
                continue
            contenttype_mime=i.get_content_type()
            att_name = i.get_filename(None)
            
            if not att_name:
                #workaround for mimetypes, it always takes .ksh for text/plain
                if i.get_content_type()=='text/plain':
                    ext='.txt'
                else:
                    ext = mimetypes.guess_extension(i.get_content_type())
                
                if ext==None:
                    ext=''
                att_name = 'noname%s' % ext
                
            #check attachment name
            #self._logger().debug('Attachment Name: %s'%att_name)
            
            
            res=self.matchMultipleSets([user_names,domain_names,default_names], att_name,suspect)
            if res==DELETE:
                return DELETE
                        
            #go through content type rules
             
            
            res=self.matchMultipleSets([user_ctypes,domain_ctypes,default_ctypes], contenttype_mime,suspect)
            if res==DELETE:
                return DELETE
            
            if MAGIC_AVAILABLE:
                pl = i.get_payload(decode=True)
                contenttype_magic=self.getBuffertype(pl)
                res=self.matchMultipleSets([user_ctypes,domain_ctypes,default_ctypes], contenttype_magic,suspect)
                if res==DELETE:
                    return DELETE
            
        return DUNNO
        
    def __str__(self):
        return "Attachment Blocker"
    
    def lint(self):
        allok=(self.checkConfig() and self.lint_magic())
        return allok
    
    def lint_magic(self):
        if not MAGIC_AVAILABLE:
            print "python-magic library not available. Will only do content-type checks, no real file analysis"
            return False
        return True
    
    
class AttachmentPluginTestCase(unittest.TestCase):
    """Testcases for the Attachment Checker Plugin"""
    def setUp(self):
        from ConfigParser import RawConfigParser        
        config=RawConfigParser()
        config.add_section('FiletypePlugin')
        config.set('FiletypePlugin', 'template_blockedfile','/etc/fuglu/templates/blockedfile.tmpl')
        config.set('FiletypePlugin', 'rulesdir','/etc/fuglu/rules')
        config.add_section('main')
        config.set('main','disablebounces','1')
        self.candidate=FiletypePlugin(config)


    def test_hiddenbinary(self):
        """Test if hidden binaries get detected correctly"""
        import tempfile
        import shutil
        
        tempfilename=tempfile.mktemp(suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy('testdata/binaryattachment.eml',tempfilename)
        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org',tempfilename)   
        
        result=self.candidate.examine(suspect)
        os.remove(tempfilename)
        self.failIf(result!=DELETE)

    def disabled_test_utf8msg(self):
        """Test utf8 msgs are parsed ok - can cause bugs on some magic implementations (eg. centos)
        disabled - need new sample"""
        import tempfile
        import shutil
        
        tempfilename=tempfile.mktemp(suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy('testdata/utf8message.eml',tempfilename)
        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org',tempfilename)   
        
        result=self.candidate.examine(suspect)
        os.remove(tempfilename)
        self.failIf(result!=DUNNO)