#   Copyright 2009-2019 Oli Schacher, Fumail Project
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
#
"""
Example prepender plugin
"""

from fuglu.shared import PrependerPlugin
from fuglu.extensions.sql import ENABLED as SQL_EXTENSION_AVAILABLE, get_session


class SQLSkipper(PrependerPlugin):

    """Example prepender plugin which skips Spamassassin based on the result of a database query


    example mysql/mariadb table:

    CREATE TABLE `spamconfig` (
     `recipient` varchar(255) NOT NULL primary key,
     `antispam_enabled` tinyint(1) NOT NULL DEFAULT 1
    );

    """

    def __init__(self, config, section=None):
        PrependerPlugin.__init__(self, config, section)
        self.requiredvars = {
            'dbconnectstring': {
                'default': 'mysql://root@localhost/test',
                'description': "sqlalchemy db connect string",
                # this will hide the value in 'fuglu_conf -n' to protect
                # confidential data
                'confidential': True,
            }
        }

    def __str__(self):
        return "SQL skipper"

    def pluginlist(self, suspect, pluginlist):
        if not SQL_EXTENSION_AVAILABLE:
            self._logger().warn(
                "SQLALCHEMY extension is not enabled, SQLSkipper will not run")
            return

        sqlsession = get_session(
            self.config.get(self.section, 'dbconnectstring'))

        self._logger().debug("Checking database overrides for %s" %
                             (suspect.recipients))

        # if postfix->fuglu is not configured with
        # xxx_destination_recipient_limit=1 the message might have multiple
        # recipients
        user_configs = sqlsession.execute(
            "SELECT recipient,antispam_enabled FROM spamconfig WHERE recipient IN :recipient", dict(recipient=tuple(suspect.recipients)))

        # if one recipient doesn't have a config, we assume antispam should run
        # normally
        if user_configs.rowcount < len(suspect.recipients):
            self._logger().debug(
                "Not all recipients have a database config - assuming normal run")
            return

        for row in user_configs:
            recipient, antispam_enabled = row
            self._logger().debug("Recipient %s anti spam enabled in database: %s" %
                                 (recipient, bool(antispam_enabled)))
            if antispam_enabled:
                # at least one user has anti spam enabled
                return

        # if we reach this point, all recipients in the message have antispam
        # disabled
        self._logger().info(
            "%s - antispam disabled by database override" % (suspect.id))
        # add other plugins you want to skip here
        skippluginlist = ['SAPlugin', ]

        listcopy = pluginlist[:]
        for plug in pluginlist:
            name = plug.__class__.__name__
            if name in skippluginlist:
                listcopy.remove(plug)
        return listcopy

    def lint(self):
        return (self.checkConfig() and self.lint_sql())

    def lint_sql(self):
        if not SQL_EXTENSION_AVAILABLE:
            print("SQLALCHEMY extension is not enabled")
            return False

        from sqlalchemy.sql.expression import func
        session = get_session(
            self.config.get(self.section, 'dbconnectstring'))
        try:
            dbtime = session.execute(func.current_timestamp()).scalar()
            print("DB connection successful. Server time: %s" % dbtime)
            session.close()
            return True
        except Exception as e:
            print(e)
            return False
