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

BASENAME="fuglu" #project name (root logger etc)
VERSION="$Id$"
CONFDIR="/etc/%s"%BASENAME
import logging
import sys
import os
import thread
import socket
import string
import tempfile
import email
import time
import traceback
import datetime
import unittest
from optparse import OptionParser
import ConfigParser
from fuglu.plugins import *
from fuglu.shared import *
import smtplib
from email.Header import Header
import threading
from threadpool import ThreadPool

HOSTNAME=socket.gethostname()

class Statskeeper( object ):
    """Keeps track of a few stats to generate mrtg graphs and stuff"""
    __shared_state = {}
    
    def __init__(self):
        self.__dict__ = self.__shared_state
        if not hasattr(self, 'totalcount'):
            self.totalcount=0
            self.spamcount=0
            self.hamcount=0
            self.viruscount=0
            self.incount=0
            self.outcount=0
            self.scantimes=[]
            self.starttime=time.time()
            self.lastscan=0
           
    def uptime(self):
        """uptime since we started fuglu"""
        total_seconds = time.time()-self.starttime
        MINUTE  = 60
        HOUR    = MINUTE * 60
        DAY     = HOUR * 24
        # Get the days, hours, etc:
        days    = int( total_seconds / DAY )
        hours   = int( ( total_seconds % DAY ) / HOUR )
        minutes = int( ( total_seconds % HOUR ) / MINUTE )
        seconds = int( total_seconds % MINUTE )
        # Build up the pretty string (like this: "N days, N hours, N minutes, N seconds")
        string = ""
        if days> 0:
            string += str(days) + " " + (days == 1 and "day" or "days" ) + ", "
        if len(string)> 0 or hours> 0:
            string += str(hours) + " " + (hours == 1 and "hour" or "hours" ) + ", "
        if len(string)> 0 or minutes> 0:
            string += str(minutes) + " " + (minutes == 1 and "minute" or "minutes" ) + ", "
        string += str(seconds) + " " + (seconds == 1 and "second" or "seconds" )
        return string;
    
    def numthreads(self):
        """return the number of threads"""
        return len(threading.enumerate())
     
    def increasecounters(self,suspect):
        """Update local counters after a suspect has passed the system"""
        self.totalcount+=1
        if suspect.is_spam():
            self.spamcount+=1
        else:
            self.hamcount+=1
        
        if suspect.is_virus():
            self.viruscount+=1
        
        scantime=suspect.get_tag('fuglu.scantime')
        self._appendscantime(scantime)
        self.lastscan=time.time()
    
    def scantime(self):
        """Get the average scantime of the last 100 messages.
        If last msg is older than five minutes, return 0"""
        tms=self.scantimes[:]
        length=len(tms)
        
        #no entries in scantime list
        if length==0:
            return "0"
        
        #newest entry is older than five minutes
        #clear entries
        if time.time()-self.lastscan>300:
            self.scantimes=[]
            return "0"
        
        avg=sum(tms)/length
        avgstring="%.4f"%avg
        return avgstring

        
    def _appendscantime(self,scantime):
        """add new entry to the list of scantimes"""
        try:
            f=float(scantime)
        except:
            return
        while len(self.scantimes)>100:
            del self.scantimes[0]
        
        self.scantimes.append(f)
        
        
class StatsThread(object):
    """Keep Track of statistics and write mrtg data"""
    def __init__(self,config):
        self.config=config
        self.stats=Statskeeper()
        self.logger=logging.getLogger('fuglu.stats')
        self.writeinterval=30
        self.identifier='FuGLU'
        self.stayalive=True
        
    def writestats(self):
        dir=self.config.get('main','mrtgdir')
        if dir==None or dir=="":
            self.logger.info('No mrtg directory defined, disabling stats writer')
            return
        
        if not os.path.isdir(dir):
            self.logger.error('MRTG directory %s not found, disabling stats writer'%dir)
            return
        
        self.logger.info('Writing statistics to %s'%dir)
        
        while self.stayalive:
            time.sleep(self.writeinterval)
            uptime=self.stats.uptime()
            
            #total messages
            self.write_mrtg('%s/inout'%dir, float(self.stats.incount), float(self.stats.outcount), uptime, self.identifier)
            #spam ham
            self.write_mrtg('%s/hamspam'%dir, float(self.stats.hamcount), float(self.stats.spamcount), uptime, self.identifier)
            
            #num threads
            self.write_mrtg('%s/threads'%dir, self.stats.numthreads(), None, uptime, self.identifier)
            
            #virus
            self.write_mrtg('%s/virus'%dir, float(self.stats.viruscount), None, uptime, self.identifier)
            
            #scan time
            self.write_mrtg('%s/scantime'%dir, self.stats.scantime(), None, uptime, self.identifier)
            
            
    
    def write_mrtg(self,filename,value1,value2,uptime,identifier):
        try:
            fp=open(filename,'w')
            fp.write("%s\n"%value1)
            if value2:
                fp.write("%s\n"%value2)
            else:
                fp.write("0\n");
            fp.write("%s\n%s\n"%(uptime,identifier))
            fp.close()
        except Exception,e:
            self.logger.error('Could not write mrtg stats file %s : %s)'%(filename,e))
    

class FUSMTPClient(smtplib.SMTP):

    """
    This class patches the sendmail method of SMTPLib so we can get the return message from postfix 
    after we have successfully re-injected. We need this so we can find out the new Queue-ID
    """
    
    def getreply(self):
        (code,response)=smtplib.SMTP.getreply(self)
        self.lastserveranswer=response
        self.lastservercode=code
        return (code,response)
       
class SessionHandler:
    """thread handling one message"""
    def __init__(self,incomingsocket,config,prependers,plugins,appenders):
        self.incomingsocket=incomingsocket
        self.logger=logging.getLogger("%s.SessionHandler"%BASENAME)
        self.action=DUNNO
        self.config=config
        self.prependers=prependers
        self.plugins=plugins
        self.appenders=appenders
        self.stats=Statskeeper()
        self.workerthread=None
        self.message=None
        
    
    def set_threadinfo(self,status):
        if self.workerthread!=None:
            self.workerthread.threadinfo=status
         
    def handlesession(self,workerthread=None):
        self.workerthread=workerthread
        
        starttime=time.time()
        sess=None
        prependheader=self.config.get('main','prependaddedheaders')
        try:
            self.set_threadinfo('receiving message')
            sess=SMTPSession(self.incomingsocket,self.config)
            success=sess.getincomingmail()
            if not success:
                self.logger.error('incoming smtp transfer did not finish')
                return
            
            self.stats.incount+=1
            fromaddr=sess.from_address
            toaddr=sess.to_address
            tempfilename=sess.tempfilename
            
            suspect=Suspect(fromaddr,toaddr,tempfilename)
            self.logger.debug("Message from %s to %s: %s bytes stored to %s"%(fromaddr,toaddr,suspect.size,tempfilename))
            self.set_threadinfo("Handling message %s"%suspect)
            #store incoming port to tag, could be used to disable plugins based on port
            try:
                port=sess.socket.getsockname()[1]
                if port is not None:
                    suspect.tags['incomingport']=port
            except Exception,e:
                self.logger.warning('Could not get incoming port: %s'%str(e))
            
            pluglist=self.run_prependers(suspect)
            
            starttime=time.time()
            self.run_plugins(suspect,pluglist)
            
            # Set fuglu spam status
            if suspect.is_spam():
                suspect.addheader("%sSpamstatus"%prependheader, 'Yes')
            else:
                suspect.addheader("%sSpamstatus"%prependheader, 'No')
            
             
            #how long did it all take?
            difftime=time.time()-starttime
            suspect.tags['fuglu.scantime']="%.4f"%difftime
            
            #Debug info to mail
            if self.config.getboolean('main','debuginfoheader'):
                debuginfo=str(suspect)
                suspect.addheader("%sDebuginfo"%prependheader, debuginfo)
            
            #add suspect id for tracking
            suspect.addheader('%sSuspect'%prependheader,suspect.id)
            
            #checks done.. print out suspect status
            self.logger.info(suspect)
            suspect.debug(suspect)
            
            #check if one of the plugins made a decision
            result=self.action
            
            self.set_threadinfo("Finishing message %s"%suspect)
            
            message_is_deferred=False
            if result==ACCEPT or result==DUNNO:
                try:
                    injectanswer=self.re_inject(suspect)
                    self.stats.outcount+=1
                    sess.endsession(250, "FUGLU REQUEUE(%s): %s"%(suspect.id,injectanswer))
                    sess=None
                except KeyboardInterrupt, k:
                    sys.exit()
                except Exception,e:
                    message_is_deferred=True
                    self.logger.error("Could not re-inject message. Error: %s"%e)
                    traceback.print_exc(file=sys.stdout)
                    sess.endsession(451, 'Internal error trying to re-inject.')
                    
                
            elif result==DELETE:
                sess.endsession(250, "OK")
                sess=None
            elif result==REJECT:
                retmesg="Rejected by content scanner"
                if self.message!=None:
                    retmesg=self.message
                sess.endsession(550,retmesg)
            elif result==DEFER:
                message_is_deferred=True
                retmesg= 'Internal problem - message deferred'
                if self.message!=None:
                    retmesg=self.message
                sess.endsession(421,retmesg)
            else:
                self.logger.error('Invalid Message action Code: %s. Using DEFER'%result)
                message_is_deferred=True
                sess.endsession(421, 'Internal problem - message deferred')
            
            
            #run appenders (stats plugin etc) unless msg is deferred
            if not message_is_deferred:
                self.stats.increasecounters(suspect)
                self.run_appenders(suspect,result)
            
            
            #clean up
            try:
                os.remove(tempfilename)
                self.logger.debug('Removed tempfile %s'%tempfilename)
            except:
                self.logger.warning('Could not remove tempfile %s'%tempfilename)
        except KeyboardInterrupt:
            sys.exit(0)    
        except Exception, e:
            self.logger.error('Exception: %s'%e)
            if sess!=None:
                sess.endsession(421, 'exception %s'%e)
        self.logger.debug('Session finished')

    
    def trash(self,suspect,killerplugin=None):
        """copy suspect to trash if this is enabled"""
        trashdir=self.config.get('main','trashdir').strip()
        if trashdir=="":
            return
        
        if not os.path.isdir(trashdir):
            self.logger.error("Trashdir %s does not exist"%trashdir)
        
        try:
            (handle,trashfilename)=tempfile.mkstemp(prefix=BASENAME,dir=self.config.get('main','trashdir'))
            trashfile=os.fdopen(handle,'w+b')
            trashfile.write(suspect.getMessageRep().as_string())
            trashfile.close()
            self.logger.debug('Message stored to trash: %s'%trashfilename)
        except Exception,e:
            self.logger.error("could not create file %s: %s"%(trashfilename,e))
        
        try:
            handle=open('%s/00-fuglutrash.log'%self.config.get('main','trashdir'),'a')
            # <date> <time> <from address> <to address> <plugin that said "DELETE"> <filename>
            time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
            handle.write("%s %s %s %s %s"%(time,suspect.from_address,suspect.to_address,killerplugin,trashfilename))
            handle.write("\n")
            handle.close()
            
        except Exception,e:
            self.logger.error("Could not update trash index: %s"%e)
        
    def re_inject(self,suspect):
        """Send message back to postfix"""
        if suspect.get_tag('noreinject'):
            return 'message not re-injected by plugin request'
        modifiedtext=self._buildmsgsource(suspect)
        
        client = FUSMTPClient('127.0.0.1',self.config.getint('main', 'outgoingport'))
        client.helo(self.config.get('main','outgoinghelo'))
  
        client.sendmail(suspect.from_address, suspect.to_address, modifiedtext)
        #if we did not get an exception so far, we can grab the server answer using the patched client
        servercode=client.lastservercode
        serveranswer=client.lastserveranswer
        try:
            client.quit()
        except Exception,e:
            self.logger.warning('Exception while quitting re-inject session: %s'%str(e))
        
        if serveranswer==None:
            self.logger.warning('Re-inject: could not get server answer.')
            serveranswer=''
        return serveranswer
        
    def _buildmsgsource(self,suspect):
        """Build the message source with fuglu headers prepended"""
        #we must prepend headers manually as we can't set a header order in email objects
        
        msgrep=suspect.getMessageRep()
        
        origmsgtxt=msgrep.as_string()
        newheaders=""
        
        for key in suspect.addheaders:
            val=unicode(suspect.addheaders[key],errors='ignore')  # is ignore the right thing to do here?
            self.logger.debug('Adding header %s : %s'%(key,val))
            hdr=Header(val, header_name=key, continuation_ws=' ')
            newheaders+="%s: %s\n"%(key,hdr.encode())
        
        modifiedtext=newheaders+origmsgtxt
        return modifiedtext
    
    def run_plugins(self,suspect,pluglist):
        """Run scannerplugins on suspect"""
        suspect.debug('Will run plugins: %s'%pluglist)
        for plugin in pluglist:
            try:
                self.logger.debug('Running plugin %s'%plugin)
                self.set_threadinfo("%s : Running Plugin %s"%(suspect,plugin))
                suspect.debug('Running plugin %s'%str(plugin))
                ans = plugin.examine(suspect)
                message=None
                if type(ans) is tuple:
                    result,message=ans
                else:
                    result=ans
                
                if result==None:
                    result=DUNNO

                suspect.tags['decisions'].append((str(plugin),result))
                
                if result==DUNNO:
                    suspect.debug('Plugin makes no final decision')
                elif result==ACCEPT:
                    suspect.debug('Plugin accepts the message - skipping all further tests')
                    self.logger.debug('Plugin says: ACCEPT. Skipping all other tests')
                    self.action=ACCEPT
                    break
                elif result==DELETE:
                    suspect.debug('Plugin DELETES this message - no further tests')
                    self.logger.debug('Plugin says: DELETE. Skipping all other tests')
                    self.action=DELETE
                    self.trash(suspect,str(plugin))
                    break
                elif result==REJECT:
                    suspect.debug('Plugin REJECTS this message - no further tests')
                    self.logger.debug('Plugin says: REJECT. Skipping all other tests')
                    self.action=REJECT
                    self.message=message
                    break
                elif result==DEFER:
                    suspect.debug('Plugin DEFERS this message - no further tests')
                    self.logger.debug('Plugin says: DEFER. Skipping all other tests')
                    self.action=DEFER
                    self.message=message
                    break
                else:
                    self.logger.error('Invalid Message action Code: %s. Using DUNNO'%result)
                    
            except Exception,e:
                exc=traceback.format_exc()
                self.logger.error('Plugin %s failed: %s'%(str(plugin),exc))
                suspect.debug('Plugin failed : %s . Please check fuglu log for more details'%e)
                
    def run_prependers(self,suspect):
        """Run prependers on suspect"""
        plugcopy=self.plugins[:]
        for plugin in self.prependers:
            try:
                self.logger.debug('Running prepender %s'%plugin)
                self.set_threadinfo("%s : Running Prepender %s"%(suspect,plugin))
                result=plugin.pluginlist(suspect,plugcopy)
                if result!=None:
                    plugcopyset=set(plugcopy)
                    resultset=set(result)
                    removed=list(plugcopyset-resultset)
                    added=list(resultset-plugcopyset)
                    if len(removed)>0:
                        self.logger.debug('Prepender %s removed plugins: %s'%(plugin,map(str,removed)))
                    if len(added)>0:
                        self.logger.debug('Prepender %s added plugins: %s'%(plugin,map(str,added)))
                    plugcopy=result
                    
            except Exception,e:
                exc=traceback.format_exc()
                self.logger.error('Prepender plugin %s failed: %s'%(str(plugin),exc))
        return plugcopy
               
    def run_appenders(self,suspect,finaldecision):
        """Run appenders on suspect"""
        if suspect.get_tag('noappenders'):
            return
        
        for plugin in self.appenders:
            try:
                self.logger.debug('Running appender %s'%plugin)
                suspect.debug('Running appender %s'%plugin)
                self.set_threadinfo("%s : Running appender %s"%(suspect,plugin))
                result=plugin.process(suspect,finaldecision)       
            except Exception,e:
                exc=traceback.format_exc()
                self.logger.error('Appender plugin %s failed: %s'%(str(plugin),exc))

class MainController:
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
                           ('main','mrtgdir')
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
        loggername="%s.%s"%(BASENAME,myclass)
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
            print "Linting Plugin ",fc.strcolor(str(plugin),'cyan')
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
            
    
    def load_plugins(self):
        """load plugins defined in config"""
        
        newplugins=[]
        newprependers=[]
        newappenders=[]
        
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
        plugins=self.config.get('main', 'plugins').split(',')
        for structured_name in plugins:
            if structured_name=="":
                continue
            try:
                plugininstance=self._load_component(structured_name)
                newplugins.append(plugininstance)
            except Exception,e:
                self._logger().error('Could not load scanner plugin %s : %s'%(structured_name,e))
                allOK=False
        
        
        self._logger().debug('Loading prepender plugins')
        plugins=self.config.get('main', 'prependers').split(',')
        for structured_name in plugins:
            if structured_name=="":
                continue
            try:
                plugininstance=self._load_component(structured_name)
                newprependers.append(plugininstance)
            except Exception,e:
                self._logger().error('Could not load prepender plugin %s : %s'%(structured_name,e))
                allOK=False
        
        
        self._logger().debug('Loading appender plugins')
        plugins=self.config.get('main', 'appenders').split(',')
        for structured_name in plugins:
            if structured_name=="":
                continue
            try:
                #from: http://mail.python.org/pipermail/python-list/2003-May/204392.html
                plugininstance=self._load_component(structured_name)
                newappenders.append(plugininstance)
            except Exception,e:
                self._logger().error('Could not load appender plugin %s : %s'%(structured_name,e))
                allOK=False
        if allOK:
            self.plugins=newplugins
            self.prependers=newprependers
            self.appenders=newappenders
            
        return allOK
    
    def _load_component(self,structured_name):
        #from: http://mail.python.org/pipermail/python-list/2003-May/204392.html
        component_names = structured_name.split('.')
        mod = __import__('.'.join(component_names[:-1]))
        for component_name in component_names[1:]:
            mod = getattr(mod, component_name)
        plugininstance=mod(self.config)
        return plugininstance
            
class SMTPServer:    
    def __init__(self, controller,port=10025,address="127.0.0.1"):
        self.logger=logging.getLogger("%s.smtp.incoming.%s"%(BASENAME,port))
        self.logger.debug('Starting incoming SMTP Server on Port %s'%port)
        self.port=port
        self.controller=controller
        self.stayalive=1
        
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((address, port))
            self._socket.listen(5)
        except Exception,e:
            self.logger.error('Could not start incoming SMTP Server: %s'%e)
            sys.exit(1)
   
   
    def shutdown(self):
        self.stayalive=False
        self._socket.close()
        
    def serve(self):
        #disable to debug... 
        use_multithreading=True
        controller=self.controller
        threading.currentThread().name='SMTP Server on Port %s'%self.port
        
        self.logger.info('SMTP Server running on port %s'%self.port)
        if use_multithreading:
                threadpool=self.controller.threadpool
        while self.stayalive:
            try:
                self.logger.debug('Waiting for connection...')
                nsd = self._socket.accept()
                if not self.stayalive:
                    break
                engine = SessionHandler(nsd[0],controller.config,controller.prependers,controller.plugins,controller.appenders)
                self.logger.debug('Incoming connection from %s'%str(nsd[1]))
                if use_multithreading:
                    #this will block if queue is full
                    threadpool.add_task(engine)
                else:
                    engine.handlesession()
            except Exception,e:
                self.logger.error('Exception in serve(): %s'%str(e))

                 
class SMTPSession:
    ST_INIT = 0
    ST_HELO = 1
    ST_MAIL = 2
    ST_RCPT = 3
    ST_DATA = 4
    ST_QUIT = 5
    
    def __init__(self, socket,config):
        self.config=config
        self.from_address=None
        self.to_address=None
        self.helo=None
        
        self.socket = socket;
        self.state = SMTPSession.ST_INIT
        self.logger=logging.getLogger("%s.smtpsession"%BASENAME)
        self.tempfile=None


    def endsession(self,code,message):
        self.socket.send("%s %s\r\n"%(code,message))
        data = ''
        completeLine = 0
        while not completeLine:
            lump = self.socket.recv(1024);
            if len(lump):
                data += lump
                if (len(data) >= 2) and data[-2:] == '\r\n':
                    completeLine = 1
                    cmd = data[0:4]
                    cmd = string.upper(cmd)
                    keep = 1
                    rv = None
                    if cmd == "QUIT":
                        self.socket.send("%s %s\r\n"%(220,"BYE"))
                        self.closeconn()
                        return
                    self.socket.send("%s %s\r\n"%(421,"Cannot accept further commands"))
                    self.closeconn()
                    return
            else:
                self.closeconn()
                return
        return
                    
        
        
    def closeconn(self):
        self.socket.close()
        
    def getincomingmail(self):
        """return true if mail got in, false on error Session will be kept open"""
        self.socket.send("220 %s scanner ready \r\n"%BASENAME)
        while 1:
            data = ''
            completeLine = 0
            while not completeLine:
                lump = self.socket.recv(1024);
                if len(lump):
                    data += lump
                    if (len(data) >= 2) and data[-2:] == '\r\n':
                        completeLine = 1
                        if self.state != SMTPSession.ST_DATA:
                            rsp, keep = self.doCommand(data)
                        else:
                            try:
                                rsp=self.doData(data)
                            except IOError:
                                self.endsession(421,"Could not write to temp file")
                                return False
                                
                            if rsp == None:
                                continue
                            else:
                                #data finished.. keep connection open though
                                self.logger.debug('incoming message finished')
                                return True

                        self.socket.send(rsp + "\r\n")
                        if keep == 0:
                            self.socket.close()
                            return False
                else:
                    # EOF
                    return False
        return False
            
    def doCommand(self, data):
        """Process a single SMTP Command"""
        cmd = data[0:4]
        cmd = string.upper(cmd)
        keep = 1
        rv = None
        if cmd == "HELO":
            self.state = SMTPSession.ST_HELO
            self.helo=data
        elif cmd == "RSET":
            self.from_address=None
            self.to_address=None
            self.helo=None
            self.dataAccum = ""
            self.state = SMTPSession.ST_INIT
        elif cmd == "NOOP":
            pass
        elif cmd == "QUIT":
            keep = 0
        elif cmd == "MAIL":
            if self.state != SMTPSession.ST_HELO:
                return ("503 Bad command sequence", 1)
            self.state = SMTPSession.ST_MAIL
            self.from_address=self.stripAddress(data)
        elif cmd == "RCPT":
            if (self.state != SMTPSession.ST_MAIL) and (self.state != SMTPSession.ST_RCPT):
                return ("503 Bad command sequence", 1)
            self.state = SMTPSession.ST_RCPT
            self.to_address=self.stripAddress(data)
        elif cmd == "DATA":
            if self.state != SMTPSession.ST_RCPT:
                return ("503 Bad command sequence", 1)
            self.state = SMTPSession.ST_DATA
            self.dataAccum = ""
            try:
                (handle,tempfilename)=tempfile.mkstemp(prefix=BASENAME,dir=self.config.get('main','tempdir'))
                self.tempfilename=tempfilename
                self.tempfile=os.fdopen(handle,'w+b')
            except Exception,e:
                self.endsession(421,"could not create file: %s"%str(e))

            return ("354 OK, Enter data, terminated with a \\r\\n.\\r\\n", 1)
        else:
            return ("505 Eh? WTF was that?", 1)

        if rv:
            return (rv, keep)
        else:
            return("250 OK", keep)

    def doData(self, data):
        #store the last few bytes in memory to keep track when the msg is finished
        self.dataAccum = self.dataAccum + data
        
        if len(self.dataAccum)>4:
            self.dataAccum=self.dataAccum[-5:]
        
        if len(self.dataAccum) > 4 and self.dataAccum[-5:] == '\r\n.\r\n':
            #check if there is more data to write tot he file
            if len(data)>4:
                self.tempfile.write(data[0:-5])
            
            self.tempfile.close()

            self.state = SMTPSession.ST_HELO
            return "250 OK - Data and terminator. found"
        else:
            self.tempfile.write(data)
            return None   
             
    def stripAddress(self,address):
        """
        Strip the leading & trailing <> from an address.  Handy for
        getting FROM: addresses.
        """
        start = address.find('<') + 1
        if start<1:
            start=address.find(':')+1
        if start<1:
            raise ValueError,"Could not parse address %s"%address
        end = string.find(address, '>')
        if end<0:
            end=len(address)
        retaddr=address[start:end]
        retaddr=retaddr.strip()
        return retaddr

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
        self.logger=logging.getLogger("%s.controlsessoin"%(BASENAME,))
        
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
        self.logger=logging.getLogger("%s.control.%s"%(BASENAME,port))
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
class DummySMTPServer(object):
    """one-time smtp server to test re-injects"""
    def __init__(self, config,port=11026,address="127.0.0.1"):
        self.logger=logging.getLogger("dummy.smtpserver")
        self.logger.debug('Starting dummy SMTP Server on Port %s'%port)
        self.port=port
        self.config=config
        
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((address, port))
        self._socket.listen(5)
        self.suspect=None
        
    def serve(self):
        nsd = self._socket.accept()
        
        sess=SMTPSession(nsd[0],self.config)
        success=sess.getincomingmail()
        if not success:
            self.logger.error('incoming smtp transfer did not finish')
            return
        sess.endsession(250, "OK - queued as 1337 ")
        
        fromaddr=sess.from_address
        
        toaddr=sess.to_address
        self.tempfilename=sess.tempfilename
        self.logger.debug("Message from %s to %s stored to %s"%(fromaddr,toaddr,self.tempfilename))
        
        self.suspect=Suspect(fromaddr,toaddr,self.tempfilename)
        




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
        sesshandler=SessionHandler(None,self.mc.config,self.mc.prependers,self.mc.plugins,self.mc.appenders)
        suspect=Suspect("oli@unittests.fuglu.org", "recipient@unittests.fuglu.org", "testdata/helloworld.eml")
        rnd=random.randint(1000,1000000)
        
        suspect.addheader('randomstuff',str(rnd))
        #longstring=''.join([random.choice(string.letters + string.digits+' ') for i in range(200)])
        longstring="The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog."
        suspect.addheader('longstring', longstring )
        msgsource=sesshandler._buildmsgsource(suspect)
        
        newrep=email.message_from_string(msgsource)
        #print msgsource
        self.failUnless(newrep['randomstuff']==str(rnd), "Header was not written correctly")
        #this seems to trigger http://bugs.python.org/issue1974 ?
        #self.failUnless(newrep['longstring']==longstring, "Long header was not written correctly: %s != %s"%(longstring,newrep['longstring']))
        
        
class EndtoEndTestTestCase(unittest.TestCase):
    """Full check if mail runs through"""
    
    def setUp(self):
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
        
 
class OtherTests(unittest.TestCase):
    """Other testcases"""
    
    
    def setUp(self):
        config=ConfigParser.RawConfigParser()
        config.add_section('main')
        config.set('main', 'disablebounces', '1')
        config.set('main', 'tempdir', '/tmp')
        self.config=config
    
    def testSMTPClient(self):
        """Test Overridden smtpclient"""
        self.smtp=DummySMTPServer(self.config, 9998, "127.0.0.1")
        thread.start_new_thread(self.smtp.serve, ())
        client=FUSMTPClient('127.0.0.1',9998)
        client.helo('test.client')
        fh=open('testdata/helloworld.eml')
        message=fh.read()
        client.sendmail('sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', message)
        ans=client.lastserveranswer
        self.failIf(ans.find('1337')<1,'Did not get dummy server answer')
        client.quit()
        
        