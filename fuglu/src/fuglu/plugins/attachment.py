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
from fuglu.shared import ScannerPlugin,Suspect, DELETE, DUNNO,\
    string_to_actioncode, actioncode_to_string
from fuglu.bounce import Bounce
import fuglu.extensions.sql
import time
import re
import mimetypes
import os
import os.path
import logging
import unittest
from fuglu.extensions.sql import DBFile

from threading import Lock

MAGIC_AVAILABLE=0
MAGIC_PYTHON_FILE=1
MAGIC_PYTHON_MAGIC=2

try:
    import magic
    #python-file or python-magic? python-magic does not have an open attribute
    if hasattr(magic,'open'):
        MAGIC_AVAILABLE=MAGIC_PYTHON_FILE
    else:
        MAGIC_AVAILABLE=MAGIC_PYTHON_MAGIC

except ImportError:
    pass


FUATT_NAMESCONFENDING="-filenames.conf"
FUATT_CTYPESCONFENDING="-filetypes.conf"

FUATT_DEFAULT=u'default'

FUATT_ACTION_ALLOW=u'allow'
FUATT_ACTION_DENY=u'deny'
FUATT_ACTION_DELETE=u'delete'

FUATT_CHECKTYPE_FN=u'filename'
FUATT_CHECKTYPE_CT=u'contenttype'

ATTACHMENT_DUNNO=0
ATTACHMENT_BLOCK=1
ATTACHMENT_OK=2
ATTACHMENT_SILENTDELETE=3

KEY_NAME=u"name"
KEY_CTYPE=u"ctype"

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
        return self.getRules(KEY_CTYPE, key)

    def getNAMERules(self,key):
        return self.getRules(KEY_NAME, key)

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
        self.logger.debug('Reloading attachment rules...')

        #set last timestamp
        statinfo=os.stat(self.rulesdir)
        ctime=statinfo.st_ctime
        self.lastreload=ctime


        filelist=os.listdir(self.rulesdir)

        newruleset={KEY_NAME:{},KEY_CTYPE:{}}

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
            type=KEY_NAME
            key=filename[0:-len(FUATT_NAMESCONFENDING)]
            if(filename.endswith(FUATT_CTYPESCONFENDING)):
                type=KEY_CTYPE
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
        handle=open(filename)
        return self.get_rules_from_config_lines(handle.readlines())

    def get_rules_from_config_lines(self,lineslist):
        ret={}
        for line in lineslist:
            line=line.strip()
            if line.startswith('#') or line=='':
                continue
            tuple=line.split(None,2)
            if (len(tuple)!=3):
                self.logger.debug('Ignoring invalid line  (length %s): %s'%(len(tuple),line))
            (action,regex,description)=tuple
            action=action.lower()
            if action not in [FUATT_ACTION_ALLOW,FUATT_ACTION_DENY,FUATT_ACTION_DELETE]:
                self.logger.error('Invalid rule action: %s'%action)
                continue

            tp=(action,regex,description)
            ret[regex]=tp
        return ret
        
class FiletypePlugin(ScannerPlugin):
    """Copy this to make a new plugin"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars=((self.section,'template_blockedfile'),(self.section,'rulesdir'))
        self.logger=self._logger()
        if MAGIC_AVAILABLE:
            if MAGIC_AVAILABLE==MAGIC_PYTHON_FILE:
                self.ms = magic.open(magic.MAGIC_MIME)
                self.ms.load()
        else:
            self.logger.warning('python-magic not available')
        self.rulescache=RulesCache(self.config.get(self.section,'rulesdir'))
        self.extremeverbosity=False

    def examine(self,suspect):
        starttime=time.time()
        self.blockedfiletemplate=self.config.get(self.section,'template_blockedfile')

        returnaction=self.walk(suspect)

        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['FiletypePlugin.time']="%.4f"%difftime
        return returnaction

    def getFiletype(self,path):
        if MAGIC_AVAILABLE==MAGIC_PYTHON_FILE:
            type=self.ms.file(path)
        elif MAGIC_AVAILABLE==MAGIC_PYTHON_MAGIC:
            type=magic.from_file(path,mime=True)
        return type

    def getBuffertype(self,buffer):
        if MAGIC_AVAILABLE==MAGIC_PYTHON_FILE:
            type=self.ms.buffer(buffer)
        elif MAGIC_AVAILABLE==MAGIC_PYTHON_MAGIC:
            type=magic.from_buffer(buffer, mime=True)
        return type


    def matchRules(self,ruleset,object,suspect,attachmentname=None):
        if attachmentname==None:
            attachmentname=""
        attachmentname="".join([x for x in attachmentname if ord(x) < 128])
        
        # remove non ascii chars
        asciirep="".join([x for x in object if ord(x) < 128])
        
        displayname=attachmentname
        if asciirep==attachmentname:
            displayname=''
        
        if ruleset==None:
            return ATTACHMENT_DUNNO

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
                    self.logger.info('suspect %s contains blocked attachment %s %s'%(suspect.id,displayname,asciirep))
                    blockinfo="%s %s: %s"%(displayname,asciirep,description)
                    if self.config.get(self.section,'sendbounce'):
                        self._logger().info("Sending attachment block bounce to %s"%suspect.from_address)
                        suspect.tags['FiletypePlugin.errormessage']=blockinfo
                        bounce=Bounce(self.config)
                        bounce.send_template_file(suspect.from_address, self.blockedfiletemplate, suspect,dict(blockinfo=blockinfo))
                    return ATTACHMENT_BLOCK

                if action=='delete':
                    self.logger.info('suspect %s contains blocked attachment %s %s -- SILENT DELETE! --'%(suspect.id,displayname,asciirep))
                    return ATTACHMENT_SILENTDELETE

                if action=='allow':
                    return ATTACHMENT_OK
        return ATTACHMENT_DUNNO


    def matchMultipleSets(self,setlist,object,suspect,attachmentname=None):
        """run through multiple sets and return the first action which matches object"""
        self._logger().debug('Checking Object %s against attachment rulesets'%object)
        for ruleset in setlist:
            res=self.matchRules(ruleset, object,suspect,attachmentname)
            if res!=ATTACHMENT_DUNNO:
                return res
        return ATTACHMENT_DUNNO

    def walk(self,suspect):
        """walks through a message and checks each attachment according to the rulefile specified in the config"""
        
        blockaction=self.config.get(self.section,'blockaction')
        blockactioncode=string_to_actioncode(blockaction)
        
        #try db rules first
        self.rulescache.reloadifnecessary()
        dbconn=''
        if self.config.has_option(self.section,'dbconnectstring'):
            dbconn=self.config.get(self.section,'dbconnectstring')
           
        if dbconn.strip()!='':
            self.logger.debug('Loading attachment rules from database')
            query=self.config.get(self.section,'query')
            dbfile=DBFile(dbconn, query)
            user_names=self.rulescache.get_rules_from_config_lines(dbfile.getContent({'scope':suspect.to_address,'checktype':FUATT_CHECKTYPE_FN}))
            user_ctypes=self.rulescache.get_rules_from_config_lines(dbfile.getContent({'scope':suspect.to_address,'checktype':FUATT_CHECKTYPE_CT}))
            self.logger.debug('Found %s filename rules, %s content-type rules for address %s'%(len(user_names),len(user_ctypes),suspect.to_address))
            domain_names=self.rulescache.get_rules_from_config_lines(dbfile.getContent({'scope':suspect.to_domain,'checktype':FUATT_CHECKTYPE_FN}))
            domain_ctypes=self.rulescache.get_rules_from_config_lines(dbfile.getContent({'scope':suspect.to_domain,'checktype':FUATT_CHECKTYPE_CT}))
            self.logger.debug('Found %s filename rules, %s content-type rules for domain %s'%(len(domain_names),len(domain_ctypes),suspect.to_domain))
        else:
            self.logger.debug('Loading attachment rules from filesystem')
            user_names=self.rulescache.getNAMERules(suspect.to_address)
            user_ctypes=self.rulescache.getCTYPERules(suspect.to_address)
    
            domain_names=self.rulescache.getNAMERules(suspect.to_domain)
            domain_ctypes=self.rulescache.getCTYPERules(suspect.to_domain)

        #always get defaults from file
        default_names=self.rulescache.getNAMERules(FUATT_DEFAULT)
        default_ctypes=self.rulescache.getCTYPERules(FUATT_DEFAULT)

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
                att_name = 'unnamed%s' % ext

            

            res=self.matchMultipleSets([user_names,domain_names,default_names], att_name,suspect,att_name)
            if res==ATTACHMENT_SILENTDELETE:
                self._debuginfo(suspect,"Attachment name=%s SILENT DELETE : blocked by name"%att_name)
                return DELETE
            if res==ATTACHMENT_BLOCK:
                self._debuginfo(suspect,"Attachment name=%s : blocked by name)"%att_name)
                return blockactioncode
            

            #go through content type rules
            res=self.matchMultipleSets([user_ctypes,domain_ctypes,default_ctypes], contenttype_mime,suspect,att_name)
            if res==ATTACHMENT_SILENTDELETE:
                self._debuginfo(suspect,"Attachment name=%s content-type=%s SILENT DELETE: blocked by mime content type (message source)"%(att_name,contenttype_mime))
                return DELETE
            if res==ATTACHMENT_BLOCK:
                self._debuginfo(suspect,"Attachment name=%s content-type=%s : blocked by mime content type (message source)"%(att_name,contenttype_mime))
                return blockactioncode
            
            if MAGIC_AVAILABLE:
                pl = i.get_payload(decode=True)
                contenttype_magic=self.getBuffertype(pl)
                res=self.matchMultipleSets([user_ctypes,domain_ctypes,default_ctypes], contenttype_magic,suspect,att_name)
                if res==ATTACHMENT_SILENTDELETE:
                    self._debuginfo(suspect,"Attachment name=%s content-type=%s SILENT DELETE: blocked by mime content type (magic)"%(att_name,contenttype_mime))
                    return DELETE
                if res==ATTACHMENT_BLOCK:
                    self._debuginfo(suspect,"Attachment name=%s content-type=%s : blocked by mime content type (magic)"%(att_name,contenttype_mime))
                    return blockactioncode
        return DUNNO

    def _debuginfo(self,suspect,message):
        """Debug to log and suspect"""
        suspect.debug(message)
        self.logger.debug(message)

    def __str__(self):
        return "Attachment Blocker"

    def lint(self):
        allok=(self.checkConfig() and self.lint_magic() and self.lint_sql())
        return allok

    def lint_magic(self):
        if not MAGIC_AVAILABLE:
            print "python-magic and python-file library not available. Will only do content-type checks, no real file analysis"
            return False
        if MAGIC_AVAILABLE==MAGIC_PYTHON_FILE:
            print "Found python-file magic library"
        if MAGIC_AVAILABLE==MAGIC_PYTHON_MAGIC:
            print "Found python-magic library"
        return True

    def lint_sql(self):
        dbconn=''
        if self.config.has_option(self.section,'dbconnectstring'):
            dbconn=self.config.get(self.section,'dbconnectstring')
        if dbconn.strip()!='':
            print "Reading per user/domain attachment rules from database"
            if not fuglu.extensions.sql.ENABLED:
                print "Fuglu SQL Extension not available, cannot load attachment rules from database"
                return False
            query=self.config.get(self.section,'query')
            dbfile=DBFile(dbconn, query)
            try:
                dbfile.getContent({'scope':'lint','checktype':FUATT_CHECKTYPE_FN})
            except Exception,e:
                import traceback
                print "Could not get attachment rules from database. Exception: %s"%str(e)
                print traceback.format_exc()
                return False
        else:
            print "No database configured. Using per user/domain file configuration from %s"%self.config.get(self.section,'rulesdir')
        return True


class DatabaseConfigTestCase(unittest.TestCase):
    """Testcases for the Attachment Checker Plugin"""
    def setUp(self):
        from ConfigParser import RawConfigParser
        import tempfile
        import shutil
        from sqlalchemy import Table, Column,  MetaData,  Unicode, Integer
        from sqlalchemy.ext.declarative import declarative_base
        
        testfile="/tmp/attachconfig.db"
        if os.path.exists(testfile):
            os.remove(testfile)
        #important: 4 slashes for absolute paths!
        testdb="sqlite:///%s"%testfile
        DeclarativeBase = declarative_base()
        metadata = DeclarativeBase.metadata
        rules_table = Table("attachmentrules", metadata,
                    Column('id', Integer, primary_key=True),
                    Column('scope', Unicode(255), nullable=False),
                    Column('checktype', Unicode(20), nullable=False),
                    Column('action', Unicode(255), nullable=False),
                    Column('regex', Unicode(255), nullable=False),
                    Column('description', Unicode(255), nullable=False),
                    Column('prio', Integer, nullable=False),
        )
        
        self.session=fuglu.extensions.sql.get_session(testdb)
        self.session.flush()
        bind=self.session.get_bind(rules_table)
        bind.connect()
        bind.engine.echo=True
        metadata.create_all(bind)
        self.tempdir=tempfile.mkdtemp('attachtestdb', 'fuglu')
        self.template='%s/blockedfile.tmpl'%self.tempdir
        shutil.copy('../conf/templates/blockedfile.tmpl.dist',self.template)
        shutil.copy('../conf/rules/default-filenames.conf.dist','%s/default-filenames.conf'%self.tempdir)
        shutil.copy('../conf/rules/default-filetypes.conf.dist','%s/default-filetypes.conf'%self.tempdir)
        config=RawConfigParser()
        config.add_section('FiletypePlugin')
        config.set('FiletypePlugin', 'template_blockedfile',self.template)
        config.set('FiletypePlugin', 'rulesdir',self.tempdir)
        config.set('FiletypePlugin','dbconnectstring',testdb)
        config.set('FiletypePlugin', 'blockaction','DELETE')
        config.set('FiletypePlugin', 'sendbounce','True')
        config.set('FiletypePlugin','query','SELECT action,regex,description FROM attachmentrules WHERE scope=:scope AND checktype=:checktype ORDER BY prio')
        config.add_section('main')
        config.set('main','disablebounces','1')
        self.candidate=FiletypePlugin(config)
    
    def test_dbrules(self):
        """Test if db rules correctly override defaults"""
        import tempfile
        import shutil

        testdata=u"""
        INSERT INTO attachmentrules(scope,checktype,action,regex,description,prio) VALUES
        ('recipient@unittests.fuglu.org','contenttype','allow','application/x-executable','this user likes exe',1)
        """
        self.session.execute(testdata)
        #copy file rules
        tempfilename=tempfile.mktemp(suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy('testdata/binaryattachment.eml',tempfilename)
        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org',tempfilename)

        result=self.candidate.examine(suspect)
        resstr=actioncode_to_string(result)
        self.assertEquals(resstr,"DUNNO")
        
        
        #another recipient should still get the block
        suspect=Suspect('sender@unittests.fuglu.org','recipient2@unittests.fuglu.org',tempfilename)

        result=self.candidate.examine(suspect)
        resstr=actioncode_to_string(result)
        self.assertEquals(resstr,"DELETE")
        os.remove(tempfilename)

class AttachmentPluginTestCase(unittest.TestCase):
    """Testcases for the Attachment Checker Plugin"""
    def setUp(self):
        from ConfigParser import RawConfigParser
        import tempfile
        import shutil

        self.tempdir=tempfile.mkdtemp('attachtest', 'fuglu')
        self.template='%s/blockedfile.tmpl'%self.tempdir
        shutil.copy('../conf/templates/blockedfile.tmpl.dist',self.template)
        shutil.copy('../conf/rules/default-filenames.conf.dist','%s/default-filenames.conf'%self.tempdir)
        shutil.copy('../conf/rules/default-filetypes.conf.dist','%s/default-filetypes.conf'%self.tempdir)
        config=RawConfigParser()
        config.add_section('FiletypePlugin')
        config.set('FiletypePlugin', 'template_blockedfile',self.template)
        config.set('FiletypePlugin', 'rulesdir',self.tempdir)
        config.set('FiletypePlugin', 'blockaction','DELETE')
        config.set('FiletypePlugin', 'sendbounce','True')
        config.add_section('main')
        config.set('main','disablebounces','1')
        self.candidate=FiletypePlugin(config)


    def tearDown(self):
        os.remove('%s/default-filenames.conf'%self.tempdir)
        os.remove('%s/default-filetypes.conf'%self.tempdir)
        os.remove(self.template)
        os.rmdir(self.tempdir)

    def test_hiddenbinary(self):
        """Test if hidden binaries get detected correctly"""
        import tempfile
        import shutil

        #copy file rules
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
        self.assertEquals(result,DUNNO)
