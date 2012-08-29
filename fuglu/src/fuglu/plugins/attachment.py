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
from fuglu.shared import ScannerPlugin,Suspect, DELETE, DUNNO, REJECT,\
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
    """This plugin checks message attachments. You can configure what filetypes or filenames are allowed to pass through fuglu. If a attachment is not allowed, the message is deleted and the sender receives a bounce error message. The plugin uses the '''file''' library to identify attachments, so even if a smart sender renames his executable to .txt, fuglu will detect it.

Attachment rules can be defined globally, per domain or per user.

Actions: This plugin will delete messages if they contain blocked attachments.

Prerequisites: You must have the python ``file`` or ``magic`` module installed


The attachment configuration files are in ``/etc/fuglu/rules``. You whould have two default files there: ``default-filenames.conf`` which defines what filenames are allowed and ``default-filetypes.conf`` which defines what content types a attachment may have. 

For domain rules, create a new file ``<domainname>-filenames.conf`` / ``<domainname>-filetypes.conf`` , eg. ``fuglu.org-filenames.conf`` / ``fuglu.org-filetypes.conf``

For individual user rules, create a new file ``<useremail>-filenames.conf`` / ``<useremail>-filetypes.conf``, eg. ``oli@fuglu.org-filenames.conf`` / ``oli@fuglu.org-filetypes.conf``

The format of those files is as follows: Each line should have three parts, seperated by tabs (or any whitespace):
<action>    <regular expression>   <description or error message>

<action> can be one of:
 * allow : this file is ok, don't do further checks (you might use it for safe content types like text). Do not blindly create 'allow' rules. It's safer to make no rule at all, if no other rules hit, the file will be accepted
 * deny : delete this message and send the error message/description back to the sender
 * delete : silently delete the message, no error is sent back, and 'blockaction' is ignored


<regular expression> is a standard python regex. in x-filenames.conf this will be applied to the attachment name . in x-filetypes.conf this will be applied to the mime type of the file as well as the file type returned by the ``file`` command.

example of default-filetypes.conf:

::

    allow    text        -        
    allow    \bscript    -        
    allow    archive        -            
    allow    postscript    -            
    deny    self-extract    No self-extracting archives
    deny    executable    No programs allowed
    deny    ELF        No programs allowed
    deny    Registry    No Windows Registry files allowed



small extract from default-filenames.conf:

::

    deny    \.ico$            Windows icon file security vulnerability    
    deny    \.ani$            Windows animated cursor file security vulnerability    
    deny    \.cur$            Windows cursor file security vulnerability    
    deny    \.hlp$            Windows help file security vulnerability
    
    allow    \.jpg$            -    
    allow    \.gif$            -    



Note: The files will be reloaded automatically after a few seconds (you do not need to kill -HUP / restart fuglu)

The bounce template (eg /etc/fuglu/templates/blockedfile.tmpl) should look like this:

::

    To: ${from_address}
    Subject: Blocked attachment
    
    Your message to ${to_address} contains a blocked attachment and has been deleted.
    
    ${blockinfo}
    
    You may add this file to a zip archive (or similar) and send it again.


eg. define headers for your message at the beginning, followed by a blank line. Then append the message body.

``${blockinfo}`` will be replaced with the text you specified in the third column of the rule that blocked this message.

See (TODO: link to template vars chapter) for commonly available template variables in Fuglu.

"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.requiredvars={
            'template_blockedfile':{
                'default':'/etc/fuglu/templates/blockedfile.tmpl',
                'description':'Mail template for the bounce to inform sender about blocked attachment',
            },
            
            'sendbounce':{
                'default':'1',
                'description':'inform the sender about blocked attachments',
            },
                         
            'rulesdir':{
                'default':'/etc/fuglu/rules',
                'description':'directory that contains attachment rules',
            },
                           
            'blockaction':{
                'default':'DELETE',
                'description':'what should the plugin do when a blocked attachment is detected\nREJECT : reject the message (recommended in pre-queue mode)\nDELETE : discard messages\nDUNNO  : mark as blocked but continue anyway (eg. if you have a later quarantine plugin)',
            },
                           
            'dbconnectstring':{
                'default':'',
                'description':'sqlalchemy connectstring to load rules from a database and use files only as fallback. requires SQL extension to be enabled',
                'confidential':True,
            },
                           
            'query':{
                'default':'SELECT action,regex,description FROM attachmentrules WHERE scope=:scope AND checktype=:checktype ORDER BY prio',
                'description':"sql query to load rules from a db. #:scope will be replaced by the recipient address first, then by the recipient domain\n:check will be replaced by either 'filename' to get filename rules or 'contenttype' to get content type rules",
            },       
        }
        
        self.logger=self._logger()
        if MAGIC_AVAILABLE:
            if MAGIC_AVAILABLE==MAGIC_PYTHON_FILE:
                self.ms = magic.open(magic.MAGIC_MIME)
                self.ms.load()
        else:
            self.logger.warning('python-magic not available')
        self.rulescache=None
        self.extremeverbosity=False

    def examine(self,suspect):
        starttime=time.time()
        if self.rulescache==None:
            self.rulescache=RulesCache(self.config.get(self.section,'rulesdir'))
        
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

    def asciionly(self,stri):
        """return stri with all non-ascii chars removed"""
        return "".join([x for x in stri if ord(x) < 128])
        

    def matchRules(self,ruleset,object,suspect,attachmentname=None):
        if attachmentname==None:
            attachmentname=""
        attachmentname=self.asciionly(attachmentname)
        
        # remove non ascii chars
        asciirep=self.asciionly(object)
        
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
                    suspect.tags['FiletypePlugin.errormessage']=blockinfo
                    if self.config.getboolean(self.section,'sendbounce'):
                        self._logger().info("Sending attachment block bounce to %s"%suspect.from_address)
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
                message=suspect.tags['FiletypePlugin.errormessage']
                return blockactioncode,message
            

            #go through content type rules
            res=self.matchMultipleSets([user_ctypes,domain_ctypes,default_ctypes], contenttype_mime,suspect,att_name)
            if res==ATTACHMENT_SILENTDELETE:
                self._debuginfo(suspect,"Attachment name=%s content-type=%s SILENT DELETE: blocked by mime content type (message source)"%(att_name,contenttype_mime))
                return DELETE
            if res==ATTACHMENT_BLOCK:
                self._debuginfo(suspect,"Attachment name=%s content-type=%s : blocked by mime content type (message source)"%(att_name,contenttype_mime))
                message=suspect.tags['FiletypePlugin.errormessage']
                return blockactioncode,message
            
            if MAGIC_AVAILABLE:
                pl = i.get_payload(decode=True)
                contenttype_magic=self.getBuffertype(pl)
                res=self.matchMultipleSets([user_ctypes,domain_ctypes,default_ctypes], contenttype_magic,suspect,att_name)
                if res==ATTACHMENT_SILENTDELETE:
                    self._debuginfo(suspect,"Attachment name=%s content-type=%s SILENT DELETE: blocked by mime content type (magic)"%(att_name,contenttype_mime))
                    return DELETE
                if res==ATTACHMENT_BLOCK:
                    self._debuginfo(suspect,"Attachment name=%s content-type=%s : blocked by mime content type (magic)"%(att_name,contenttype_mime))
                    message=suspect.tags['FiletypePlugin.errormessage']
                    return blockactioncode,message
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
        
        testfile="/tmp/attachconfig.db"
        if os.path.exists(testfile):
            os.remove(testfile)
        #important: 4 slashes for absolute paths!
        testdb="sqlite:///%s"%testfile
        
        sql="""create table attachmentrules(
        id integer not null primary key,
        scope varchar(255) not null,
        checktype varchar(20) not null,
        action varchar(255) not null,
        regex varchar(255) not null,
        description varchar(255) not null,
        prio integer not null
        )
        """ 

        self.session=fuglu.extensions.sql.get_session(testdb)
        self.session.flush()
        self.session.execute(sql)
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
        if type(result) is tuple:
            result,message=result
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
        if type(result) is tuple:
            result,message=result
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
        if type(result) is tuple:
            result,message=result
        os.remove(tempfilename)
        self.assertEquals(result,DUNNO)
