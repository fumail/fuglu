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
from string import Template
import logging
modlogger=logging.getLogger('fuglu.extensions.sql')
ENABLED=False
STATUS="not loaded"
try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker
    ENABLED=True
    modlogger.info('sql extension enabled')
    STATUS="available"
    
except:
    modlogger.warning('sqlalchemy not installed, not enabling sql extension')
    STATUS="sqlalchemy not installed"

    
def get_session(connectstring):
    global sessions,ENABLED
    if not ENABLED:
        raise Exception,"sql extension not enabled"

    engine = create_engine(connectstring)
    maker = sessionmaker(autoflush=True, autocommit=True)
    session = scoped_session(maker)
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
        buffer=[]
        for row in res:
            line=" ".join(row)
            buffer.append(line)
        return buffer