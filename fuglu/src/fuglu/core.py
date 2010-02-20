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

VERSION="$Id$"
CONFDIR="/etc/fuglu"
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
#from smtpconnector import SMTPServer,SMTPSession,FUSMTPClient
from smtpconnector import SMTPServer
from fuglu.stats import StatsThread
from fuglu.scansession import SessionHandler

HOSTNAME=socket.gethostname()




class MainController(object):
    """main class to startup and control the app"""
    plugins=[]
    prependers=[]
    appenders=[]
    config=None
    
    def __init__(self,config):
        self.requiredvars=(('performance','minthreads'),
                           ('performance','maxthreads'),
                           ('main','user'),
                           ('main','group'),
                           ('main','disablebounces'),
                           ('main','trashdir'),
                           ('main','daemonize'),
                           ('main','plugindir'),
                           ('main','plugins'),
                           ('main','prependers'),
                           ('main','appenders'),
                           ('main','incomingport'),
                           ('main','bindaddress'),
                           ('main','outgoingport'),
                           ('main','outgoinghelo'),
                           ('main','tempdir'),
                           ('main','prependaddedheaders'),
                           ('main','mrtgdir'),
                           ('spam','defaultlowspamaction'),
                           ('spam','defaulthighspamaction'),
                           ('virus','defaultvirusaction'),
                           )
        self.config=config
        self.smtpservers=[]
        self.logger=self._logger()
        self.stayalive=True
        self.threadpool=None
        self.controlserver=None
        self.started=datetime.datetime.now()
        self.statsthread=None
        
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
        
        self.logger.info("Init SMTP Engine")
        
        
        #TODO: load multiple connectors
        ports=self.config.get('main', 'incomingport')
        for port in ports.split(','):
            port=int(port.strip())
            smtpserver=SMTPServer(self,port=port,address=self.config.get('main', 'bindaddress'))
            thread.start_new_thread(smtpserver.serve, ())
            self.smtpservers.append(smtpserver)
            
        #control socket
        #TODO: port config...
        control=ControlServer(self,address=self.config.get('main', 'bindaddress'))
        thread.start_new_thread(control.serve, ())
        self.controlserver=control
        
        self.logger.info('Startup complete')
        while self.stayalive:
            try:
                time.sleep(10)
            except KeyboardInterrupt:
                self.shutdown()
    
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
            for serv in self.smtpservers:
                if serv.port==port:
                    alreadyRunning=True
                    break
            
            if not alreadyRunning:
                smtpserver=SMTPServer(self,port=port,address=self.config.get('main', 'bindaddress'))
                thread.start_new_thread(smtpserver.serve, ())
                self.smtpservers.append(smtpserver)
        
        servercopy=self.smtpservers[:] 
        for serv in servercopy:
            if serv.port not in portlist:
                self.logger.info('Closing server socket on port %s'%serv.port)
                serv.shutdown()
                self.smtpservers.remove(serv)
        
        self.logger.info('Config changes applied')
    
            
    def shutdown(self):
        self.statsthread.stayalive=False
        for server in self.smtpservers:
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
                print "ERROR: %s"%e
                result=False
            
            if result:
                print fc.strcolor("OK","green")
            else:
                errors=errors+1
                print fc.strcolor("ERROR","red")
        print "%s plugins reported errors."%errors
        
        
    
    def checkConfig(self):
        """Check if all requred options are in the config file"""
        allOK=True
        for configvar in self.requiredvars:
            (section,config)=configvar
            try:
                var=self.config.get(section,config)
            except ConfigParser.NoSectionError:
                print "Missing configuration section [%s] :: %s"%(section,config)
                allOK=False
            except ConfigParser.NoOptionError:
                print "Missing configuration value [%s] :: %s"%(section,config)
                allOK=False
        
        outgoinghelocheck="change.me.in.fuglu.conf.local"       
        if self.config.get('main','outgoinghelo')==outgoinghelocheck:
            print "Your outgoing helo still says '%s' - you should change this option to a real fqdn "%outgoinghelocheck
            allOK=False
        
            
        return allOK
    
    
    def load_extensions(self):
        """load fuglu extensions"""
        ret=[]
        import fuglu.extensions
        for extension in fuglu.extensions.__ALL__:
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
            
        return allOK
    
    def _load_all(self,configstring):
        """load all plugins from config string. returns tuple ([list of loaded instances],allOk)"""
        pluglist=[]
        config_re=re.compile("""^(?P<structured_name>[a-zA-Z0-9\.\_]+)(?:\((?P<config_override>[a-zA-Z0-9\.\_]+)\))?$""")
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
            except Exception,e:
                self._logger().error('Could not load plugin %s : %s'%(structured_name,e))
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
            

class ControlSession(object):
    def __init__(self,socket,controller):
        self.controller=controller
        self.socket=socket
        self.commands={
                       'workerlist':self.workerlist,
                       'threadlist':self.threadlist,
                       'uptime':self.uptime,
                       'stats':self.stats
                       }
        self.logger=logging.getLogger('fuglu.controlsession')
        
    def handlesession(self):
        line=self.socket.recv(4096).lower().strip()
        if line=='':
            self.socket.close()
            return
    
        self.logger.debug('Control Socket command: %s'%line)
        parts=line.split()    
        answer=self.handle_command(parts[0], parts[1:])
        self.socket.sendall(answer)
        self.socket.close()
    
    def handle_command(self,command,args):
        if not self.commands.has_key(command):
            return "ERR no such command"
        
        res=self.commands[command](args)
        return res
    
    def workerlist(self,args):
        """list of mail scanning workers"""
        threadpool=self.controller.threadpool
        workerlist="\n%s"%'\n*******\n'.join(map(repr,threadpool.workers))
        res="Total %s Threads\n%s"%(len(threadpool.workers),workerlist)
        return res
    
    def threadlist(self,args):
        """list of all threads"""
        threads=threading.enumerate()
        workerlist="\n%s"%'\n*******\n'.join(map(repr,threads))
        res="Total %s Threads\n%s"%(len(threads),workerlist)
        return res
    
    def uptime(self,args):
        start=self.controller.started
        diff=datetime.datetime.now()-start
        return "Fuglu was started on %s\nUptime: %s"%(start,diff)
    
    def stats(self,args):
        start=self.controller.started
        runtime=datetime.datetime.now()-start
        stats=self.controller.statsthread.stats
        template="""Fuglu statistics
---------------
Uptime:\t\t${uptime}
Avg scan time:\t${scantime}
Total msgs:\t${totalcount}
Ham:\t\t${hamcount}
Spam:\t\t${spamcount}
Virus:\t\t${viruscount}
        """
        renderer=string.Template(template)
        vars=dict(
                  uptime=runtime,
                  scantime=stats.scantime(),
                  totalcount=stats.totalcount,
                  hamcount=stats.hamcount,
                  viruscount=stats.viruscount,
                  spamcount=stats.spamcount
                  )
        res=renderer.safe_substitute(vars)
        return res
    
        
class ControlServer(object):    
    def __init__(self, controller,port=10010,address="127.0.0.1"):
        self.logger=logging.getLogger("fuglu.control.%s"%port)
        self.logger.debug('Starting Control/Info server on port %s'%port)
        self.port=port
        self.controller=controller
        self.stayalive=1
        
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((address, port))
            self._socket.listen(5)
        except Exception,e:
            self.logger.error('Could not start control server: %s'%e)
            sys.exit(1)
   
   
    def shutdown(self):
        self.stayalive=False
        self._socket.close()
        
    def serve(self):
        threading.currentThread().name='ControlServer Thread'
        controller=self.controller
        
        self.logger.info('Control/Info Server running on port %s'%self.port)
        while self.stayalive:
            try:
                self.logger.debug('Waiting for connection...')
                nsd = self._socket.accept()
                if not self.stayalive:
                    break
                engine = ControlSession(nsd[0],controller)
                self.logger.debug('Incoming connection from %s'%str(nsd[1]))
                engine.handlesession()
                
            except Exception,e:
                self.logger.error('Exception in serve(): %s'%str(e))     



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
        from fuglu.smtpconnector import buildmsgsource
        msgsource=buildmsgsource(suspect)
        
        newrep=email.message_from_string(msgsource)
        #print msgsource
        self.failUnless(newrep['randomstuff']==str(rnd), "Header was not written correctly")
        #this seems to trigger http://bugs.python.org/issue1974 ?
        #self.failUnless(newrep['longstring']==longstring, "Long header was not written correctly: %s != %s"%(longstring,newrep['longstring']))
        
        
class EndtoEndTestTestCase(unittest.TestCase):
    """Full check if mail runs through"""
    
    def setUp(self):
        from smtpconnector import DummySMTPServer
        self.config=ConfigParser.RawConfigParser()
        self.config.read(['testdata/endtoendtest.conf'])
        
        #init core
        self.mc=MainController(self.config)
        
        #start listening smtp dummy server to get fuglus answer
        self.smtp=DummySMTPServer(self.config, self.config.getint('main', 'outgoingport'), "127.0.0.1")
        thread.start_new_thread(self.smtp.serve, ())
        
        #start fuglus listening server
        thread.start_new_thread(self.mc.startup, ())
    
    def tearDown(self):
        self.mc.shutdown()
        
    
    
    
    def testE2E(self):
        """test if a standard message runs through"""
        from email.mime.text import MIMEText

        #give fuglu time to start listener
        time.sleep(1)
        
        #send test message
        smtpServer = smtplib.SMTP('127.0.0.1',self.config.getint('main', 'incomingport'))
        #smtpServer.set_debuglevel(1)
        smtpServer.helo('test.e2e')
        testmessage="""Hello World!\r
Don't dare you change any of my bytes or even remove one!"""
        
        #TODO: this test fails if we don't put in the \r in there... (eg, fuglu adds it) - is this a bug or wrong test?
        
        msg = MIMEText(testmessage)
        msg["Subject"]="End to End Test"
        msgstring=msg.as_string()
        inbytes=len(msg.get_payload())
        smtpServer.sendmail('sender@fuglu.org', 'recipient@fuglu.org', msgstring)
        smtpServer.quit()
        
        #get answer
        gotback=self.smtp.suspect
        self.failIf(gotback ==None, "Did not get message from dummy smtp server")
        
        #check a few things on the received message
        msgrep=gotback.getMessageRep()
        self.failUnless(msgrep.has_key('X-Fuglutest-Spamstatus'), "Fuglu SPAM Header not found in message")
        payload=msgrep.get_payload()
        outbytes=len(payload)
        self.failUnlessEqual(testmessage, payload, "Message body has been altered. In: %s bytes, Out: %s bytes, teststring=->%s<- result=->%s<-"%(inbytes,outbytes,testmessage,payload))
        
 

        
        