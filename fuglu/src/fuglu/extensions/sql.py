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


sessions={}
    
def get_session(connectstring):
    global sessions,ENABLED
    if not ENABLED:
        raise Exception,"sql extension not enabled"
    
    if sessions.has_key(connectstring):
        return sessions[connectstring]
    else:
        engine = create_engine(connectstring)
        maker = sessionmaker(autoflush=True, autocommit=True)
        session = scoped_session(maker)
        session.configure(bind=engine)
        sessions[connectstring]=session
        return session