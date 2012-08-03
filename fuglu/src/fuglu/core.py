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


import sys
import thread
import string
import tempfile
import unittest
import ConfigParser
from fuglu.plugins import *
from fuglu.shared import *
import smtplib
import threading
from threadpool import ThreadPool
import inspect
import traceback
import time

from fuglu.connectors.smtpconnector import SMTPServer
from fuglu.connectors.milterconnector import MilterServer
from fuglu.connectors.ncblackholeconnector import NCServer
from fuglu.connectors.esmtpconnector import ESMTPServer

from fuglu.stats import StatsThread
from fuglu.scansession import SessionHandler
from fuglu.debug import ControlServer, CrashStore


class MainController(object):
    """main class to startup and control the app"""
    plugins=[]
    prependers=[]
    appenders=[]
    config=None
    
    def __init__(self,config):        
        self.requiredvars={
            #main section
            'identifier':{
              'section':'main',
              'description':"""identifier can be any string that helps you identifying your config file\nthis helps making sure the correct config is loaded. this identifier will be printed out when fuglu is reloading its config""",
              'default':'dist',
            },
                           
            'daemonize':{
              'section':'main',
              'description':"run as a daemon? (fork)",
              'default':"1",
              #todo: validator...?
            },
                           
            'user':{
              'section':'main',
              'description':"run as user",
              'default':"nobody",
              #todo: validator, check user...?
            },  
                           
            'group':{
              'section':'main',
              'description':"run as group",
              'default':"nobody",
              #todo: validator, check user...?
            },   
                           
           'plugindir':{
              'section':'main',
              'description':"where should fuglu search for additional plugins",
              'default':"",
            },
                           
            'plugins':{
              'section':'main',
              'description':"what SCANNER plugins do we load, comma separated",
              'default':"archive,attachment,clamav,spamassassin",
            },
            
            'prependers':{
              'section':'main',
              'description':"what PREPENDER plugins do we load, comma separated",
              'default':"debug,skip",
            },
            
            'appenders':{
              'section':'main',
              'description':"what APPENDER plugins do we load, comma separated\nappender plugins are plugins run after the scanning plugins\nappenders will always be run, even if a a scanner plugin decided to delete/bounce/whatever a message\n(unless a mail is deferred in which case running the appender would not make sense as it will come again)",
              'default':"",
            },
            
            'bindaddress':{
              'section':'main',
              'description':"address fuglu should listen on. usually 127.0.0.1 so connections are accepted from local host only",
              'default':"127.0.0.1",
            },
                              
            'incomingport':{
              'section':'main',
              'description':"incoming port(s) (postfix connects here)\nyou can use multiple comma separated ports here\nf.ex. to separate incoming and outgoing mail and a special port for debugging messages\n10025: standard incoming mail\n10099: outgoing mail\n10888: debug port",
              'default':"10025,10099,10888",
            },
            
            'outgoingport':{
              'section':'main',
              'description':"outgoing port (what port does postfix listen for re-injects)",
              'default':"10026",
            },
                
            'outgoinghelo':{
              'section':'main',
              'description':"#outgoing helo we should use for re-injects\nleave empty to auto-detect current hostname",
              'default':"",
            },
            
            'tempdir':{
              'section':'main',
              'description':"temp dir where fuglu can store messages while scanning",
              'default':"/tmp",
            },
                           
            'prependaddedheaders':{
              'section':'main',
              'description':"String to prepend to added headers",
              'default':"X-Fuglu-",
            },
            
            'trashdir':{
              'section':'main',
              'description':"If a plugin decides to delete a message, save a copy here\ndefault empty, eg. do not save a backup copy",
              'default':"",
            },
                           
            'trashlog':{
              'section':'main',
              'description':"list all deleted messages in 00-fuglutrash.log in the trashdir",
              'default':"0",
            },
            
            'disablebounces':{
              'section':'main',
              'description':"if this is set to True/1/yes , no Bounces will be sent from Fuglu eg. after a blocked attachment has been detected\nThis may be used for debugging/testing to make sure fuglu can not produce backscatter",
              'default':"0",
            },
            
            'debuginfoheader':{
              'section':'main',
              'description':"write debug info header to every mail",
              'default':"0",
            },
                           
            'mrtgdir':{
              'section':'main',
              'description':"write mrtg statistics",
              'default':"",
            },
          
            #performance section
            'minthreads':{
                'default':"2",
                'section':'performance',
                'description':'minimum scanner threads',
            },
            'maxthreads':{
                'default':"40",
                'section':'performance',
                'description':'maximum scanner threads',
            }, 
                           
                           
            #spam section
            'defaultlowspamaction':{
                'default':"DUNNO",
                'section':'spam',
                'description':"""what to do with messages that plugins think are spam but  not so sure  ("low spam")\nin normal usage you probably never set this something other than DUNNO\nthis is a DEFAULT action, eg. anti spam plugins should take this if you didn't set \n a individual override""",
            }, 
                           
            'defaulthighspamaction':{
                'default':"DUNNO",
                'section':'spam',
                'description':"""what to do with messages if a plugin is sure it is spam ("high spam") \nin after-queue mode this is probably still DUNNO or maybe DELETE for courageous people\nthis is a DEFAULT action, eg. anti spam plugins should take this if you didn't set\n a individual override """,
            },
            
            #virus section
             'defaultvirusaction':{
                'default':"DELETE",
                'section':'virus',
                'description':"""#what to do with messages if a plugin detects a virus\nin after-queue mode this should probably be DELETE\nin pre-queue mode you could use REJECT\nthis is a DEFAULT action, eg. anti-virus plugins should take this if you didn't set \n a individual override""",
            },
                           
            #smtpconnector
             'requeuetemplate':{
                'default':"FUGLU REQUEUE(${id}): ${injectanswer}",
                'section':'smtpconnector',
                'description':"""confirmation template sent back to the connecting postfix for accepted messages""",
            },
            
            #esmtpconnector
             'queuetemplate':{
                'default':"${injectanswer}",
                'section':'esmtpconnector',
                'description':"""confirmation template sent back to the connecting client for accepted messages""",
            },
            
            #  plugin alias
             'debug':{
                'default':"fuglu.plugins.p_debug.MessageDebugger",
                'section':'PluginAlias',
            },
                           
             'skip':{
                'default':"fuglu.plugins.p_skipper.PluginSkipper",
                'section':'PluginAlias',
            },
                           
            'archive':{
                'default':"fuglu.plugins.archive.ArchivePlugin",
                'section':'PluginAlias',
            },
            
            'attachment':{
                'default':"fuglu.plugins.attachment.FiletypePlugin",
                'section':'PluginAlias',
            }, 
                           
            'clamav':{
                'default':"fuglu.plugins.clamav.ClamavPlugin",
                'section':'PluginAlias',
            },
                           
            'spamassassin':{
                'default':"fuglu.plugins.sa.SAPlugin",
                'section':'PluginAlias',
            },
                                       
            'vacation':{
                'default':"fuglu.plugins.vacation.VacationPlugin",
                'section':'PluginAlias',
            },
                           
            'actionoverride':{
                'default':"fuglu.plugins.actionoverride.ActionOverridePlugin",
                'section':'PluginAlias',
            }, 
                           
            'icap':{
                'default':"fuglu.plugins.icap.ICAPPlugin",
                'section':'PluginAlias',
            }, 
            
            'sssp':{
                'default':"fuglu.plugins.sssp.SSSPPlugin",
                'section':'PluginAlias',
            },
                           
            'fprot':{
                'default':"fuglu.plugins.fprot.FprotPlugin",
                'section':'PluginAlias',
            },         
        }
        
        self.config=config
        self.servers=[]
        self.logger=self._logger()
        self.stayalive=True
        self.threadpool=None
        self.controlserver=None
        self.started=datetime.datetime.now()
        self.statsthread=None
        self.debugconsole=False
        
    def _logger(self):
        myclass=self.__class__.__name__
        loggername="fuglu.%s"%(myclass,)
        return logging.getLogger(loggername)
    
    def startup(self):
        self.load_extensions()
        ok=self.load_plugins()
        if not ok:
            sys.stderr.write("Some plugins failed to load, please check the logs. Aborting.\n")
            self.logger.info('Fuglu shut down after fatal error condition')
            sys.exit(1)
        self.logger.info("Init Stat Engine")
        self.statsthread=StatsThread(self.config)
        thread.start_new_thread(self.statsthread.writestats, ())
        
        
        self.logger.info("Init Threadpool")
        try:
            minthreads=self.config.getint('performance','minthreads')
            maxthreads=self.config.getint('performance','maxthreads')
        except ConfigParser.NoSectionError:
            self.logger.warning('Performance section not configured, using default thread numbers')
            minthreads=1
            maxthreads=3
        
        queuesize=maxthreads*10
        self.threadpool=ThreadPool(minthreads, maxthreads, queuesize)
        
        self.logger.info("Starting interface sockets...")
        ports=self.config.get('main', 'incomingport')
        for port in ports.split(','):
            port=port.strip()
            protocol='smtp'
            
            if port.find(':')>0:
                (protocol,port)=port.split(':')
            
            port=int(port)
            if protocol=='smtp':
                smtpserver=SMTPServer(self,port=port,address=self.config.get('main', 'bindaddress'))
                thread.start_new_thread(smtpserver.serve, ())
                self.servers.append(smtpserver)
            elif protocol=='esmtp': #experimental
                esmtpserver=ESMTPServer(self,port=port,address=self.config.get('main', 'bindaddress'))
                thread.start_new_thread(esmtpserver.serve, ())
                self.servers.append(esmtpserver)
            elif protocol=='milter': #experimental
                milterserver=MilterServer(self,port=port,address=self.config.get('main', 'bindaddress'))
                thread.start_new_thread(milterserver.serve, ())
                self.servers.append(milterserver)
            elif protocol=='netcat':
                ncserver=NCServer(self,port=port,address=self.config.get('main', 'bindaddress'))
                thread.start_new_thread(ncserver.serve, ())
                self.servers.append(ncserver)
            else:
                self.logger.error('Unknown Interface Protocol: %s, ignoring server on port %s'%(protocol,port))
            
            
        #control socket
        if self.config.has_option('main', 'controlport'):
            controlport=self.config.getint('main','controlport')
        else:
            controlport=None
            
        control=ControlServer(self,address=self.config.get('main', 'bindaddress'),port=controlport)
        thread.start_new_thread(control.serve, ())
        self.controlserver=control
        
        self.logger.info('Startup complete')
        if self.debugconsole:
            self.run_debugconsole()            
        else:
            #mainthread dummy loop
            while self.stayalive:
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    self.stayalive=False
        self.shutdown()
    
    def run_debugconsole(self):
        import readline
        import code
        from fuglu.shared import DUNNO,ACCEPT,DELETE,REJECT,DEFER,Suspect
        print "Fuglu Interactive Console started"
        print ""
        print "pre-defined locals:"
        
        mc=self
        print "mc : maincontroller"
        
        terp=code.InteractiveConsole(locals())
        terp.interact("")
        
    
    def reload(self):
        """apply config changes"""
        self.logger.info('Applying configuration changes...')
        
        #threadpool changes?
        minthreads=self.config.getint('performance','minthreads')
        maxthreads=self.config.getint('performance','maxthreads')
        
        if self.threadpool.minthreads!=minthreads or self.threadpool.maxthreads!=maxthreads:
            self.logger.info('Threadpool config changed, initialising new threadpool')
            queuesize=maxthreads*10
            currentthreadpool=self.threadpool
            self.threadpool=ThreadPool(minthreads, maxthreads, queuesize)
            currentthreadpool.stayalive=False
            
        #smtp engine changes?
        ports=self.config.get('main', 'incomingport')
        portlist=map(int,ports.split(','))
        
        for port in portlist:
            alreadyRunning=False
            for serv in self.servers:
                if serv.port==port:
                    alreadyRunning=True
                    break
            
            if not alreadyRunning:
                smtpserver=SMTPServer(self,port=port,address=self.config.get('main', 'bindaddress'))
                thread.start_new_thread(smtpserver.serve, ())
                self.servers.append(smtpserver)
        
        servercopy=self.servers[:] 
        for serv in servercopy:
            if serv.port not in portlist:
                self.logger.info('Closing server socket on port %s'%serv.port)
                serv.shutdown()
                self.servers.remove(serv)
        
        self.logger.info('Config changes applied')
    
            
    def shutdown(self):
        self.statsthread.stayalive=False
        for server in self.servers:
            self.logger.info('Closing server socket on port %s'%server.port)
            server.shutdown()
        
        if self.controlserver!=None:
            self.controlserver.shutdown()
            
        self.threadpool.stayalive=False
        self.stayalive=False
        self.logger.info('Shutdown complete')
        self.logger.info('Remaining threads: %s' %threading.enumerate())
        
   
   
    def lint(self):
        errors=0
        from fuglu.funkyconsole import FunkyConsole
        fc=FunkyConsole()
        print fc.strcolor('Loading extensions...','magenta')
        exts=self.load_extensions()
        for ext in exts:
            (name,enabled,status)=ext
            pname=fc.strcolor(name,'cyan')
            if enabled:
                penabled=fc.strcolor('enabled','green')
            else:
                penabled=fc.strcolor('disabled','red')
            print "%s: %s (%s)"%(pname,penabled,status)
            
        print fc.strcolor('Loading plugins...','magenta')
        if not self.load_plugins():
            print fc.strcolor('At least one plugin failed to load','red')
        print fc.strcolor('Plugin loading complete','magenta')
         
        print "Linting ",fc.strcolor("main configuration",'cyan')
        if not self.checkConfig():
            print fc.strcolor("ERROR","red")
        else:
            print fc.strcolor("OK","green")
    
        
        trashdir=self.config.get('main','trashdir').strip()
        if trashdir!="":
            if not os.path.isdir(trashdir):
                print fc.strcolor("Trashdir %s does not exist"%trashdir,'red')
              
        
        allplugins=self.plugins+self.prependers+self.appenders
        
        for plugin in allplugins:
            print
            print "Linting Plugin ",fc.strcolor(str(plugin),'cyan'),'Config section:',fc.strcolor(str(plugin.section),'cyan')
            try:
                result=plugin.lint()
            except Exception,e:
                CrashStore.store_exception()
                print "ERROR: %s"%e
                result=False
            
            if result:
                print fc.strcolor("OK","green")
            else:
                errors=errors+1
                print fc.strcolor("ERROR","red")
        print "%s plugins reported errors."%errors
        
    
    
    def propagate_defaults(self,requiredvars,config,defaultsection=None):
        """propagate defaults from requiredvars if they are missing in config"""
        for option,infodic in requiredvars.iteritems():
            if 'section' in infodic:
                section=infodic['section']
            else:
                section=defaultsection
                
            default=infodic['default']
            
            if not config.has_section(section):
                config.add_section(section)
                
            if not config.has_option(section,option):
                config.set(section,option,default)
    
    def propagate_core_defaults(self):
        """check for missing core config options and try to fill them with defaults
        must be called before we can do plugin loading stuff
        """
        self.propagate_defaults(self.requiredvars, self.config,'main')
    
    def propagate_plugin_defaults(self):
        """propagate defaults from loaded lugins"""
        #plugins, prependers, appenders
        allplugs=self.plugins+self.prependers+self.appenders
        for plug in allplugs:
            if hasattr(plug,'requiredvars'):
                requiredvars=getattr(plug,'requiredvars')
                if type(requiredvars)==dict:
                        self.propagate_defaults(requiredvars, self.config, plug.section)
            
    
    def checkConfig(self):
        """Check if all requred options are in the config file
        Fill missing values with defaults if possible
        """
        allOK=True
        for config,infodic in self.requiredvars.iteritems():
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
    
    
    def load_extensions(self):
        """load fuglu extensions"""
        ret=[]
        import fuglu.extensions
        for extension in fuglu.extensions.__all__:
            mod = __import__('fuglu.extensions.%s'%extension)
            ext=getattr(mod,'extensions')
            fl=getattr(ext,extension)
            enabled=getattr(fl,'ENABLED')
            status=getattr(fl,'STATUS')
            name=getattr(fl,'__name__')
            ret.append(( name,enabled,status))
        return ret
    
    def get_component_by_alias(self,pluginalias):
        """Returns the full plugin component from an alias. if this alias is not configured, return the original string"""
        if not self.config.has_section('PluginAlias'):
            return pluginalias
        
        if not self.config.has_option('PluginAlias', pluginalias):
            return pluginalias
        
        return self.config.get('PluginAlias', pluginalias)
    
    def load_plugins(self):
        """load plugins defined in config"""
        allOK=True
        plugdir=self.config.get('main', 'plugindir').strip()
        if plugdir!="" and not os.path.isdir(plugdir):
            self._logger().warning('Plugin directory %s not found'%plugdir)
        
        if plugdir!="":   
            self._logger().debug('Searching for additional plugins in %s'%plugdir)
            if plugdir not in sys.path:
                sys.path.insert(0,plugdir)
            
        self._logger().debug('Module search path %s'%sys.path)
        self._logger().debug('Loading scanner plugins')
        newplugins,loadok=self._load_all(self.config.get('main', 'plugins'))
        if not loadok:
            allOK=False
        
        newprependers,loadok=self._load_all(self.config.get('main', 'prependers'))
        if not loadok:
            allOK=False
        
        newappenders,loadok=self._load_all(self.config.get('main', 'appenders'))
        if not loadok:
            allOK=False

        if allOK:
            self.plugins=newplugins
            self.prependers=newprependers
            self.appenders=newappenders
            self.propagate_plugin_defaults()
            
        return allOK
    
    def _load_all(self,configstring):
        """load all plugins from config string. returns tuple ([list of loaded instances],allOk)"""
        pluglist=[]
        config_re=re.compile("""^(?P<structured_name>[a-zA-Z0-9\.\_\-]+)(?:\((?P<config_override>[a-zA-Z0-9\.\_]+)\))?$""")
        allOK=True
        plugins=configstring.split(',')
        for plug in plugins:
            if plug=="":
                continue
            m=config_re.match(plug)
            if m==None:
                self.logger.error('Invalid Plugin Syntax: %s'%plug)
                allOK=False
                continue
            structured_name,configoverride=m.groups()
            structured_name=self.get_component_by_alias(structured_name)
            try:
                plugininstance=self._load_component(structured_name,configsection=configoverride)
                pluglist.append(plugininstance)
            except (ConfigParser.NoSectionError,ConfigParser.NoOptionError):
                CrashStore.store_exception()
                self._logger().error("The plugin %s is accessing the config in __init__ -> can not load default values"%structured_name)
            except Exception,e:
                CrashStore.store_exception()
                self._logger().error('Could not load plugin %s : %s'%(structured_name,e))
                exc=traceback.format_exc()
                self._logger().error(exc)
                allOK=False
        
        return pluglist,allOK
    
    def _load_component(self,structured_name,configsection=None):
        #from: http://mail.python.org/pipermail/python-list/2003-May/204392.html
        component_names = structured_name.split('.')
        mod = __import__('.'.join(component_names[:-1]))
        for component_name in component_names[1:]:
            mod = getattr(mod, component_name)
        
        if configsection==None:
            plugininstance=mod(self.config)
        else:
            #check if plugin supports config override
            if 'section' in inspect.getargspec(mod.__init__)[0]:
                plugininstance=mod(self.config,section=configsection)
            else:
                raise Exception,'Cannot set Config Section %s : Plugin %s does not support config override'%(configsection,mod)
        return plugininstance



############################## UNIT TESTS ##########################################



class AllpluginTestCase(unittest.TestCase):
    """Tests that all plugins should pass"""
    def setUp(self):     
        config=ConfigParser.RawConfigParser()
        config.read(['../conf/fuglu.conf.dist'])
        config.set('main', 'disablebounces', '1')
        
        self.mc=MainController(config)
        self.tempfiles=[]
 
    def tearDown(self):
        for tempfile in self.tempfiles:
            os.remove(tempfile)       

    def test_virus(self):
        """Test if eicar is detected as virus"""
        from fuglu.shared import Suspect
        import shutil
        
        self.mc.load_plugins()
        if len(self.mc.plugins)==0:
            raise Exception,"plugins not loaded"
        
        sesshandler=SessionHandler(None,self.mc.config,self.mc.prependers,self.mc.plugins,self.mc.appenders)
        tempfilename=tempfile.mktemp(suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy('testdata/eicar.eml',tempfilename)
        self.tempfiles.append(tempfilename)
        suspect=Suspect('sender@unittests.fuglu.org','recipient@unittests.fuglu.org',tempfilename)   
        pluglist=sesshandler.run_prependers(suspect)
        self.failIf(len(pluglist)==0, "Viruscheck will fail, pluginlist empty after run_prependers")
        sesshandler.run_plugins(suspect,pluglist)
        self.failUnless(suspect.is_virus(), "Eicar message was not detected as virus")
        

    def test_writeheaders(self):
        import random
        suspect=Suspect("oli@unittests.fuglu.org", "recipient@unittests.fuglu.org", "testdata/helloworld.eml")
        rnd=random.randint(1000,1000000)
        
        suspect.addheader('randomstuff',str(rnd))
        #longstring=''.join([random.choice(string.letters + string.digits+' ') for i in range(200)])
        longstring="The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog."
        suspect.addheader('longstring', longstring )
        from fuglu.connectors.smtpconnector import buildmsgsource
        msgsource=buildmsgsource(suspect)
        
        newrep=email.message_from_string(msgsource)
        #print msgsource
        self.failUnless(newrep['randomstuff']==str(rnd), "Header was not written correctly")
        #this seems to trigger http://bugs.python.org/issue1974 ?
        #self.failUnless(newrep['longstring']==longstring, "Long header was not written correctly: %s != %s"%(longstring,newrep['longstring']))
        
     
class EndtoEndTestTestCase(unittest.TestCase):
    """Full check if mail runs through"""
    
    FUGLU_PORT=7711
    DUMMY_PORT=7712
    FUGLUCONTROL_PORT=7713
    
    def setUp(self):
        from fuglu.connectors.smtpconnector import DummySMTPServer
        self.config=ConfigParser.RawConfigParser()
        self.config.read(['testdata/endtoendtest.conf'])
        self.config.set('main','incomingport',str(EndtoEndTestTestCase.FUGLU_PORT))
        self.config.set('main','outgoingport',str(EndtoEndTestTestCase.DUMMY_PORT))
        self.config.set('main','controlport',str(EndtoEndTestTestCase.FUGLUCONTROL_PORT))
        #init core
        self.mc=MainController(self.config)
        
        #start listening smtp dummy server to get fuglus answer
        self.smtp=DummySMTPServer(self.config, EndtoEndTestTestCase.DUMMY_PORT, "127.0.0.1")
        thread.start_new_thread(self.smtp.serve, ())
        
        #start fuglus listening server
        thread.start_new_thread(self.mc.startup, ())
    
    def tearDown(self):
        self.mc.shutdown()
        self.smtp.shutdown()
    
    
    def testE2E(self):
        """test if a standard message runs through"""
        from email.mime.text import MIMEText

        #give fuglu time to start listener
        time.sleep(1)
        
        #send test message
        smtpclient = smtplib.SMTP('127.0.0.1',EndtoEndTestTestCase.FUGLU_PORT)
        #smtpServer.set_debuglevel(1)
        smtpclient.helo('test.e2e')
        testmessage="""Hello World!\r
Don't dare you change any of my bytes or even remove one!"""
        
        #TODO: this test fails if we don't put in the \r in there... (eg, fuglu adds it) - is this a bug or wrong test?
        
        msg = MIMEText(testmessage)
        msg["Subject"]="End to End Test"
        msgstring=msg.as_string()
        inbytes=len(msg.get_payload())
        smtpclient.sendmail('sender@fuglu.org', 'recipient@fuglu.org', msgstring)
        smtpclient.quit()
        
        #get answer
        gotback=self.smtp.suspect
        self.failIf(gotback ==None, "Did not get message from dummy smtp server")
        
        #check a few things on the received message
        msgrep=gotback.getMessageRep()
        self.failUnless(msgrep.has_key('X-Fuglutest-Spamstatus'), "Fuglu SPAM Header not found in message")
        payload=msgrep.get_payload()
        outbytes=len(payload)
        self.failUnlessEqual(testmessage, payload, "Message body has been altered. In: %s bytes, Out: %s bytes, teststring=->%s<- result=->%s<-"%(inbytes,outbytes,testmessage,payload))


class DKIMTestCase(unittest.TestCase):
    """DKIM Sig Test"""
    
    FUGLU_PORT=7731
    DUMMY_PORT=7732
    FUGLUCONTROL_PORT=7733
    
    def setUp(self):

        from fuglu.connectors.smtpconnector import DummySMTPServer
        self.config=ConfigParser.RawConfigParser()
        self.config.read(['testdata/endtoendtest.conf'])
        self.config.set('main','incomingport',str(DKIMTestCase.FUGLU_PORT))
        self.config.set('main','outgoingport',str(DKIMTestCase.DUMMY_PORT))
        self.config.set('main','controlport',str(DKIMTestCase.FUGLUCONTROL_PORT))
        #init core
        self.mc=MainController(self.config)
        
        #start listening smtp dummy server to get fuglus answer
        self.smtp=DummySMTPServer(self.config, self.config.getint('main', 'outgoingport'), "127.0.0.1")
        thread.start_new_thread(self.smtp.serve, ())
        
        #start fuglus listening server
        thread.start_new_thread(self.mc.startup, ())
    
    def tearDown(self):
        self.mc.shutdown()
        self.smtp.shutdown()
      
    def testDKIM(self):
        #give fuglu time to start listener
        time.sleep(1)
        inputfile='testdata/helloworld.eml'
        msgstring=open(inputfile,'r').read()
        from fuglu.lib.patcheddkimlib import verify,sign
        import cStringIO
        
        dkimheader=sign(msgstring,'whatever','testfuglu.org',open('testdata/dkim/testfuglu.org.private').read(),include_headers=['From','To'])
        signedcontent=dkimheader+msgstring        
        logbuffer=cStringIO.StringIO()
        self.assertTrue(verify(signedcontent,debuglog=logbuffer),"Failed DKIM verification immediately after signing %s"%logbuffer.getvalue())
        
        
        #send test message
        try:
            smtpclient = smtplib.SMTP('127.0.0.1',DKIMTestCase.FUGLU_PORT)
        except Exception,e:
            self.fail("Could not connect to fuglu on port %s : %s"%(DKIMTestCase.FUGLU_PORT,str(e)))
        #smtpServer.set_debuglevel(1)
        smtpclient.helo('test.dkim')
        
        
        smtpclient.sendmail('sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', signedcontent)
        
        smtpclient.quit()
        
        #verify the smtp server stored the file correctly
        tmpfile=self.smtp.tempfilename
        
        result=open(tmpfile,'r').read()
        logbuffer=cStringIO.StringIO()
        verify_ok=verify(result,debuglog=logbuffer)
        self.assertTrue(verify_ok,"Failed DKIM verification: %s"%logbuffer.getvalue())

class SMIMETestCase(unittest.TestCase):
    """Email Signature Tests"""
    
    FUGLU_PORT=7721
    DUMMY_PORT=7722
    FUGLUCONTROL_PORT=7723
    
    def setUp(self):
        time.sleep(5)
        from fuglu.connectors.smtpconnector import DummySMTPServer
        self.config=ConfigParser.RawConfigParser()
        self.config.read(['testdata/endtoendtest.conf'])
        self.config.set('main','incomingport',str(SMIMETestCase.FUGLU_PORT))
        self.config.set('main','outgoingport',str(SMIMETestCase.DUMMY_PORT))
        self.config.set('main','controlport',str(SMIMETestCase.FUGLUCONTROL_PORT))
        #init core
        self.mc=MainController(self.config)
        
        #start listening smtp dummy server to get fuglus answer
        self.smtp=DummySMTPServer(self.config, SMIMETestCase.DUMMY_PORT, "127.0.0.1")
        thread.start_new_thread(self.smtp.serve, ())
        
        #start fuglus listening server
        thread.start_new_thread(self.mc.startup, ())
    
    def tearDown(self):
        self.mc.shutdown()
        self.smtp.shutdown()
        
    def testSMIME(self):
        """test if S/MIME mails still pass the signature"""
        
        #give fuglu time to start listener
        time.sleep(1)
        
        #send test message
        smtpclient = smtplib.SMTP('127.0.0.1',SMIMETestCase.FUGLU_PORT)
        #smtpServer.set_debuglevel(1)
        smtpclient.helo('test.smime')
        inputfile='testdata/smime/signedmessage.eml'
        (status,output)=self.verifyOpenSSL(inputfile)
        self.assertTrue(status==0,"Testdata S/MIME verification failed: \n%s"%output)
        msgstring=open(inputfile,'r').read()
        smtpclient.sendmail('sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', msgstring)
        
        smtpclient.quit()
        
        #verify the smtp server stored the file correctly
        tmpfile=self.smtp.tempfilename
        
        #self.failUnlessEqual(msgstring, tmpcontent, "SMTP Server did not store the tempfile correctly: %s"%tmpfile)
        (status,output)=self.verifyOpenSSL(tmpfile)
        self.assertTrue(status==0,"S/MIME verification failed: \n%s\n tmpfile is:%s"%(output,tmpfile))

    def verifyOpenSSL(self,file):
        import commands
        (status,output)=commands.getstatusoutput("openssl smime -verify -noverify -in %s"%file)
        return (status,output)
        