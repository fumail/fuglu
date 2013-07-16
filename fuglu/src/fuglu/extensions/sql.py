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
#
# Fuglu SQLAlchemy Extension
#
from ConfigParser import RawConfigParser
try:
    import cStringIO as StringIO
except:
    import StringIO

import unittest
import logging
import traceback
import os
from fuglu.shared import default_template_values, Suspect

modlogger=logging.getLogger('fuglu.extensions.sql')
ENABLED=False
STATUS="not loaded"
try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker
    ENABLED=True
    STATUS="available"
    
except:
    STATUS="sqlalchemy not installed"


_sessmaker=None
_engines = {}

def get_session(connectstring,**kwargs):
    global ENABLED
    global _sessmaker
    global _engines
    
    if not ENABLED:
        raise Exception,"sql extension not enabled"

    if connectstring in _engines:
        engine=_engines[connectstring]
    else:
        engine = create_engine(connectstring,pool_recycle=20)
        _engines[connectstring]=engine
    
    if _sessmaker==None:
        _sessmaker = sessionmaker(autoflush=True, autocommit=True,**kwargs)
    
    session = scoped_session(_sessmaker)
    session.configure(bind=engine)
    return session


class DBFile(object):
    """A DB File allows storing configs in any rdbms. """
    
    def __init__(self,connectstring,query):
        self.connectstring=connectstring
        #eg. "select action,regex,description FROM tblname where scope=:scope
        self.query=query
        self.logger=logging.getLogger('fuglu.sql.dbfile')
        
    def getContent(self,templatevars=None):
        """Get the content from the database as a list of lines. If the query returns multiple columns, they are joined together with a space as separator
        templatevars: replace placeholders in the originalquery , eg. select bla from bla where domain=:domain
        """
        if templatevars==None:
            templatevars={}
        sess=get_session(self.connectstring)
        res=sess.execute(self.query,templatevars)
        self.logger.debug('Executing query %s with vars %s'%(self.query,templatevars))
        buff=[]
        for row in res:
            line=" ".join(row)
            buff.append(line)
        sess.close()
        return buff
    
    
class DBConfig(RawConfigParser):
    """Runtime Database Config Overrides. Behaves like a RawConfigParser but returns global database overrides/domainoverrides/useroverrides if available       
    """
    
    def __init__(self,config,suspect):
        RawConfigParser.__init__(self)
        self.suspect=suspect
        self.logger=logging.getLogger('fuglu.sql.dbconfig')
        self.cloneFrom(config)
        
    
    def cloneFrom(self,config):
        """Clone this object from a RawConfigParser"""
        stringout=StringIO.StringIO()
        config.write(stringout)
        stringin=StringIO.StringIO(stringout.getvalue())
        del stringout
        self.readfp(stringin)
        del stringin
    
    def get(self,section,option):
        if not ENABLED:
            #self.logger.debug('sqlalchemy extension not enabled')
            return self.parentget(section, option)
        
        if not self.has_section('databaseconfig'):
            #self.logger.debug('no database configuration section')
            return self.parentget(section, option)
        
        if not self.has_option('databaseconfig', 'dbconnectstring'):
            #self.logger.debug('no db connect string')
            return self.parentget(section, option)
            
        connectstring=self.parentget('databaseconfig', 'dbconnectstring')
        if connectstring.strip()=='':
            #self.logger.debug('empty db connect string')
            return self.parentget(section, option)
        
        session=get_session(connectstring)
        query=self.parentget('databaseconfig', 'sql')
        if query.strip()=='':
            return self.parentget(section, option)
        
        sqlvalues={
                   'section':section,
                   'option':option,
        }
        default_template_values(self.suspect,sqlvalues)
        
        result=None
        try:
            #self.logger.debug("Executing query '%s' with vars %s"%(query,sqlvalues))
            result=session.execute(query,sqlvalues).first()
        except:
            trb=traceback.format_exc()
            self.logger.error("Error getting database config override: %s"%trb)
        
        session.remove()
        if result==None:
            #self.logger.debug('no result')
            return self.parentget(section, option)
        else:
            #self.logger.debug('result: '+result[0])
            return result[0]
  
    def parentget(self,section,option):
        return RawConfigParser.get(self, section, option)
  
  
class DBConfigTestCase(unittest.TestCase):
    """Test Templates"""
    def setUp(self):     
        self.testfile="/tmp/fuglu_override_test.db"
        if os.path.exists(self.testfile):
            os.remove(self.testfile)
        #important: 4 slashes for absolute paths!
        self.testdb="sqlite:///%s"%self.testfile
        
        config=RawConfigParser()
        config.add_section('databaseconfig')
        config.set('databaseconfig', 'dbconnectstring',self.testdb)
        config.set('databaseconfig',"sql", "SELECT value FROM fugluconfig WHERE section=:section AND option=:option AND scope IN ('$GLOBAL','%'||:to_domain,:to_address) ORDER BY SCOPE DESC")
        self.config=config
        self.create_database()

    def create_database(self):
        sql="""
        CREATE TABLE fugluconfig (
           scope varchar(255) NOT NULL,
           section varchar(255) NOT NULL,
           option varchar(255) NOT NULL,
           value varchar(255) NOT NULL 
        )
        """
        self.exec_sql(sql)
        
    def clear_table(self):
        self.exec_sql("DELETE FROM fugluconfig")
    
    def exec_sql(self,sql,values=None):
        if values==None:
            values={}
        session=get_session(self.testdb)
        session.execute(sql,values)
        session.remove()
 
    def insert_override(self,scope,section,option,value):
        sql="INSERT INTO fugluconfig (scope,section,option,value) VALUES (:scope,:section,:option,:value)"
        values=dict(scope=scope,section=section,option=option,value=value)
        self.exec_sql(sql, values)
        
    def tearDown(self):
        os.remove(self.testfile)     

    def test_user_override(self):
        """Test basic config overrdide functionality"""
        suspect=Suspect(u'sender@unittests.fuglu.org','recipient@unittests.fuglu.org','/dev/null')
        
        candidate=DBConfig(self.config, suspect)
        
        candidate.add_section('testsection')
        candidate.set('testsection', 'nooverride', '100')
        candidate.set('testsection', 'override', '100')
        
        self.clear_table()
        self.insert_override('recipient@unittests.fuglu.org', 'testsection', 'override', '200')
        self.insert_override('%unittests.fuglu.org', 'testsection', 'override', '300')
        self.insert_override('$GLOBAL', 'testsection', 'override', '400')
        self.assertEqual(candidate.getint('testsection', 'nooverride'), 100)
        self.assertEqual(candidate.getint('testsection', 'override'), 200)
       
       
    def test_domain_override(self):
        """Test basic config overrdide functionality"""
        suspect=Suspect(u'sender@unittests.fuglu.org','someotherrec@unittests.fuglu.org','/dev/null')
        
        candidate=DBConfig(self.config, suspect)
        
        candidate.add_section('testsection')
        candidate.set('testsection', 'nooverride', '100')
        candidate.set('testsection', 'override', '100')
        
        self.clear_table()
        self.insert_override('recipient@unittests.fuglu.org', 'testsection', 'override', '200')
        self.insert_override('%unittests.fuglu.org', 'testsection', 'override', '300')
        self.insert_override('$GLOBAL', 'testsection', 'override', '400')
        self.assertEqual(candidate.getint('testsection', 'nooverride'), 100)
        self.assertEqual(candidate.getint('testsection', 'override'), 300) 
   
      
    def test_global_override(self):
        """Test basic config overrdide functionality"""
        suspect=Suspect(u'sender@unittests.fuglu.org','someotherrec@unittests2.fuglu.org','/dev/null')
        
        candidate=DBConfig(self.config, suspect)
        
        candidate.add_section('testsection')
        candidate.set('testsection', 'nooverride', '100')
        candidate.set('testsection', 'override', '100')
        
        self.clear_table()
        self.insert_override('recipient@unittests.fuglu.org', 'testsection', 'override', '200')
        self.insert_override('%unittests.fuglu.org', 'testsection', 'override', '300')
        self.insert_override('$GLOBAL', 'testsection', 'override', '400')
        self.assertEqual(candidate.getint('testsection', 'nooverride'), 100)
        self.assertEqual(candidate.getint('testsection', 'override'), 400)   