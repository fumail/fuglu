#   Copyright 2012 Oli Schacher
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
import threading
import sys
import time
import socket
import logging
import datetime
import traceback
import string

class ControlServer(object):    
    def __init__(self, controller,port=None,address="127.0.0.1"):
        if port==None:
            port=10010
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
        self.logger.info("Control Server on port %s shutting down"%self.port)
        try:
            self._socket.shutdown()
            self._socket.close()
            time.sleep(3)
        except:
            pass
        
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


class ControlSession(object):
    def __init__(self,socket,controller):
        self.controller=controller
        self.socket=socket
        self.commands={
                       'workerlist':self.workerlist,
                       'threadlist':self.threadlist,
                       'uptime':self.uptime,
                       'stats':self.stats,
                       'exceptionlist':self.exceptionlist,
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
    
    def exceptionlist(self,args):
        """return last stacktrace"""
        excstring=""
        i=0
        for excinfo,thetime,threadinfo in CrashStore.exceptions:
            i+=1
            fmt=traceback.format_exception(*excinfo)
            timestr=datetime.datetime.fromtimestamp(thetime).ctime()
            excstring=excstring+"\n[%s] %s : %s\n"%(i,timestr,threadinfo)
            excstring=excstring+"".join(fmt)
        return excstring
    
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
        vrs=dict(
                  uptime=runtime,
                  scantime=stats.scantime(),
                  totalcount=stats.totalcount,
                  hamcount=stats.hamcount,
                  viruscount=stats.viruscount,
                  spamcount=stats.spamcount
                  )
        res=renderer.safe_substitute(vrs)
        return res
    

class CrashStore(object):
    exceptions=[]
    
    @staticmethod
    def store_exception(exc_info=None,thread=None):
        if exc_info==None:
            exc_info=sys.exc_info()
            
        if thread==None:
            thread=threading.currentThread()
        
        name=thread.getName()
        info=""
        if hasattr(thread,'threadinfo'):
            info=thread.threadinfo
        desc="%s (%s)"%(name,info)
        
        maxtracebacks=10
        CrashStore.exceptions.append((exc_info,time.time(),desc),)
        while len(CrashStore.exceptions)>maxtracebacks:
            CrashStore.exceptions.pop(0)
            
            