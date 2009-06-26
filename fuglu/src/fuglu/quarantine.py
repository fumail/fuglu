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
# $Id: quarantine.py 7 2009-04-09 06:51:25Z oli $
#
import rpyc
import logging
import sys
import datetime
import os
import re
import ConfigParser

class MetaData(object):
    def init_from_metafile(self,filename):
        p=ConfigParser.ConfigParser()
        p.read(filename)
        """
           cp.set('mail', 'from_address', suspect.from_address)
        cp.set('mail', 'to_address', suspect.to_address)
        cp.set('mail', 'timestamp', suspect.timestamp)
        cp.set('mail', 'id', suspect.id)
        cp.set('mail', 'isspam',suspect.is_spam())
        cp.set('mail', 'isvirus',suspect.is_virus())
        cp.set('mail', 'subject',msgrep['Subject'])
        cp.set('mail', 'size',len(msgrep))
        cp.set('mail', 'hidden',0)
        """
        
        #TODO: implement
    
    def init_from_dict(self,dct):
        pass
        #TODO: implement
    
    def __init__(self):
        self.isspam=0
        self.isvirus=0
        self.subject=""
        self.size=0
        self.id=None
        self.from_address=None
        self.to_address=None
        self.timestamp=None
        self.hidden=0
        
    

class QuarantineManager(object):
    def __init__(self):
        self.db=None
        self.lock=threading.RLock()
        #TODO: config ... read from normal fuglu conf?
        self.dbname='/usr/local/fuglu/quarantine/quarantine.db'
        self.quardir='/usr/local/fuglu/quarantine'
        self.logger=logging.getLogger('QuarantineMgr')
        
    def initdb(self):
        if self.db!=None:
            return
        
        #make sure only one thread can do this at a time
        self.lock.acquire(True)
        try:
            if not os.path.isfile(self.dbname):
                self.createdb()
            if self.db==None:
                self.db=sqlite3.connect(self.dbname)
        finally:
            self.lock.release()
    
    def getPayloadByID(self,msgid):
        return self.getPayloadByFilename(self.getFilenameByID(msgid))
    
    def getPayloadByFilename(self,filename):
        """Returns Content of filename (relative to quardir) """
        if filename==None:
            return None
        self.logger.debug('Payload request: %s'%filename)
        #TODO: check for ../ here? directory traversing...
        fullpath=self.quardir+"/"+filename
        if not os.path.exists(fullpath):
            self.logger.warning('Requested payload does not exist: %s'%filename)
            return None
        fp=open(fullpath,'r')
        content=fp.read()
        fp.close()
        return content
    
    
    def getMetaByID(self,msgid):
        basefile=self.getFilenameByID(msgid)
        if basefile==None:
            return None
        return self.getMetaByFilename(basefile+".meta")
    
    def getMetaByFilename(self,filename):
        if filename==None:
            return None
        #TODO: check for ../ here? directory traversing...
        fullpath=self.quardir+"/"+filename
        if not os.path.exists(fullpath):
            return None
        
        m=MetaData()
        m.init_from_metafile(fullpath)
        return m
        
    def getFilenameByID(self,msgid):
        c=self.db.cursor()
        c.execute('''SELECT time_stamp,to_domain FROM quarantine WHERE id=? ''',(msgid))
        ts=None
        for row in c:
            ts=row[0]
            to_domain=row[1]
        c.close()
        if ts==None:
            return None
        filename='%s/%s/%s'%(to_domain,self.ts2day(ts),msgid)
        return filename
    
    def ts2day(self,timestamp):
        dt=datetime.datetime.fromtimestamp(timestamp)
        tsname=dt.strftime('%Y%m%d')
        return tsname
    
    
    def createdb(self):
        conn = sqlite3.connect(self.dbname)
        c=conn.cursor()
        sql=["""
        create table quarantine (
            msgid char(32) not null primary key,
            from_address varchar(100),
            from_domain varchar(50) not null,
            to_address varchar(100) not null,
            to_domain varchar(50) not null,
            time_stamp long not null,
            isspam int(1) not null default 0,
            isvirus int(0) not null default 0,
            subject varchar(100),
            size int not null,
            hidden int(1) not null default 0,
        )
        """,
        """create index tod_idx on quarantine(to_domain)""",
        ]
        c.execute(sql)
        conn.commit()
        c.close()
        conn.close()
    
    def is_meta(self,filename):
        if filename.endswith('.meta'):
            return True
        return False
    
    def is_msg(self,filename):
        return re.match(r"([a-fA-F\d]{32})", filename)
    
    def rebuild(self,domain=None,daystring=None,delete=False,fast=True):
        """Sync data to db
        Reads data from metafiles (if present), tries to rebuild then otherwise
        daystring: a list of days to rebuild (string in form "yyyymmdd""), None = all available
        domain: a list of domains to rebuild, None = all
        delete: check for entries that are in the db but not on the filesystem, delete them
        fast: in each dir, compare only the number of files to the number of entries in the db, if this number matches, do not attempt rebuild
        """
        
        #check if we have a domain
        if domain==None:
            self.rebuild(domain=os.listdir(self.quardir), daystring=daystring, delete=delete, fast=fast)
            return
        
        #check if we have a day
        if domain==None:
            self.rebuild(domain=os.listdir("%s/%s"%(self.quardir,domain)), daystring=daystring, delete=delete, fast=fast)
            return
        
        self.logger.info('Rebuilding domain %s day %s delete=%s fast=%s'%(domain,daystring,delete,fast))
        
        #read dir
        builddir='%s/%s/%s'%(self.quardir,domain,daystring)
        if not os.path.exists(builddir):
            #TODO: delete option would match here...
            self.logger.error('Can not rebuild %s/%s - path %s does not exist'%(domain,daystring,builddir))
            return
        
        #get all files in builddir
        filelist=os.path.listdir(builddir)
        msgs=filter(self.is_msg,filelist)
        for msgid in msgs:
            self.logger.debug('Analyzing message %s'%msgid)
            meta='%s.meta'%msgid
            if not meta in filelist:
                self.logger.warning('No meta file found for message %s - rebuilding')
                self._buildmeta('%s/%s'%(builddir,msgid))
            
            #read meta
            metarelpath='%s/%s/%s'%(domain,daystring,meta)
            metadata=self.getMetaByFilename(metarelpath)
            if metadata==None:
                self.logger.error('No meta available for msgid %s - skipping'%msgid)
                continue
            #TODO: check db, insert
            
            
            
    def buildmeta(self,messagepath):
        """
        msgrep=suspect.getMessageRep()
        cp=ConfigParser.ConfigParser()
        cp.add_section('mail')
        cp.set('mail', 'from_address', suspect.from_address)
        cp.set('mail', 'to_address', suspect.to_address)
        cp.set('mail', 'timestamp', suspect.timestamp)
        cp.set('mail', 'id', suspect.id)
        cp.set('mail', 'isspam',suspect.is_spam())
        cp.set('mail', 'isvirus',suspect.is_virus())
        cp.set('mail', 'subject',msgrep['Subject'])
        cp.set('mail', 'size',len(msgrep))
        cp.set('mail', 'hidden',0)
        cp.write(open(filename,'w'))
        """
        #we have the id in the mesagepath... 
        #try to get info from db, if not possible, get from file...?
        #TODO implement

    def release(self,id,hide=True):
        """re-inject msg"""
        pass