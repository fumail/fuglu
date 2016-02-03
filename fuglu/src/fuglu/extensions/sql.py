#   Copyright 2009-2016 Oli Schacher
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
# Fuglu SQLAlchemy Extension
#
try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

try:
    from cStringIO import StringIO
except ImportError:
    try:
        from StringIO import StringIO
    except ImportError:
        from io import StringIO

import logging
import sys
import traceback
from fuglu.shared import default_template_values

modlogger = logging.getLogger('fuglu.extensions.sql')
ENABLED = False
STATUS = "not loaded"
try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker
    ENABLED = True
    STATUS = "available"

except:
    STATUS = "sqlalchemy not installed"


_sessmaker = None
_engines = {}


def get_session(connectstring, **kwargs):
    global ENABLED
    global _sessmaker
    global _engines

    if not ENABLED:
        raise Exception("sql extension not enabled")

    if connectstring in _engines:
        engine = _engines[connectstring]
    else:
        engine = create_engine(connectstring, pool_recycle=20)
        _engines[connectstring] = engine

    if _sessmaker == None:
        _sessmaker = sessionmaker(autoflush=True, autocommit=True, **kwargs)

    session = scoped_session(_sessmaker)
    session.configure(bind=engine)
    return session


class DBFile(object):

    """A DB File allows storing configs in any rdbms. """

    def __init__(self, connectstring, query):
        self.connectstring = connectstring
        # eg. "select action,regex,description FROM tblname where scope=:scope
        self.query = query
        self.logger = logging.getLogger('fuglu.sql.dbfile')

    def getContent(self, templatevars=None):
        """Get the content from the database as a list of lines. If the query returns multiple columns, they are joined together with a space as separator
        templatevars: replace placeholders in the originalquery , eg. select bla from bla where domain=:domain
        """
        if templatevars == None:
            templatevars = {}
        sess = get_session(self.connectstring)
        res = sess.execute(self.query, templatevars)
        self.logger.debug('Executing query %s with vars %s' %
                          (self.query, templatevars))
        buff = []
        for row in res:
            line = " ".join(filter(None, row))
            buff.append(line)
        sess.close()
        return buff


class DBConfig(RawConfigParser):

    """Runtime Database Config Overrides. Behaves like a RawConfigParser but returns global database overrides/domainoverrides/useroverrides if available       
    """

    def __init__(self, config, suspect):
        RawConfigParser.__init__(self)
        self.suspect = suspect
        self.logger = logging.getLogger('fuglu.sql.dbconfig')
        self.cloneFrom(config)

    def cloneFrom(self, config):
        """Clone this object from a RawConfigParser"""
        stringout = StringIO()
        config.write(stringout)
        stringin = StringIO(stringout.getvalue())
        del stringout
        if sys.version_info < (3, 2):
            self.readfp(stringin)
        else:
            self.read_file(stringin)
        del stringin

    def get(self, section, option):
        if not ENABLED:
            #self.logger.debug('sqlalchemy extension not enabled')
            return self.parentget(section, option)

        if not self.has_section('databaseconfig'):
            #self.logger.debug('no database configuration section')
            return self.parentget(section, option)

        if not self.has_option('databaseconfig', 'dbconnectstring'):
            #self.logger.debug('no db connect string')
            return self.parentget(section, option)

        connectstring = self.parentget('databaseconfig', 'dbconnectstring')
        if connectstring.strip() == '':
            #self.logger.debug('empty db connect string')
            return self.parentget(section, option)

        session = get_session(connectstring)
        query = self.parentget('databaseconfig', 'sql')
        if query.strip() == '':
            return self.parentget(section, option)

        sqlvalues = {
            'section': section,
            'option': option,
        }
        default_template_values(self.suspect, sqlvalues)

        result = None
        try:
            #self.logger.debug("Executing query '%s' with vars %s"%(query,sqlvalues))
            result = session.execute(query, sqlvalues).first()
        except:
            trb = traceback.format_exc()
            self.logger.error(
                "Error getting database config override: %s" % trb)

        session.remove()
        if result == None:
            #self.logger.debug('no result')
            return self.parentget(section, option)
        else:
            #self.logger.debug('result: '+result[0])
            return result[0]

    def parentget(self, section, option):
        return RawConfigParser.get(self, section, option)
