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
#
#
from fuglu.shared import PrependerPlugin


class MessageDebugger(PrependerPlugin):

    """Message Debugger Plugin (Prepender).

This plugin enables the fuglu_debug functionality. Make sure fuglu listens on the debug port configured here.    
"""

    def __init__(self, config, section=None):
        PrependerPlugin.__init__(self, config, section)
        if self.section == 'MessageDebugger':
            self.section = 'debug'

        self.filter = None
        self.logger = self._logger()

        self.requiredvars = {
            'debugport': {
                'default': '10888',
                'description': 'messages incoming on this port will be debugged to a logfile\nMake sure the debugport is also set in the incomingport configuration option in the main section',
            },

            'debugfile': {
                'default': '/tmp/fuglu_debug.log',
                'description': "debug log output",
            },

            'nobounce': {
                'default': '1',
                'description': 'debugged message can not be bounced',
            },

            'noreinject': {
                'default': '1',
                'description': "don't re-inject debugged messages back to postfix",
            },

            'noappender': {
                'default': '1',
                'description': "don't run appender plugins for debugged messages",
            },
        }

    def lint(self):
        debugport = self.config.get(self.section, 'debugport')
        incomingport = self.config.get('main', 'incomingport')

        allok = self.checkConfig()

        if debugport not in incomingport.split(','):
            print(
                "Debug port %s not specified in [main]::incomingport - messages can't be debugged" % debugport)
            allok = False

        return allok

    def __str__(self):
        return "Debugger"

    def pluginlist(self, suspect, pluginlist):
        debugport = self.config.getint(self.section, 'debugport')
        if suspect.get_tag('incomingport') == debugport:
            self.logger.info(
                'Enabling debug mode for message on incoming port %s' % debugport)
            if self.config.getboolean(self.section, 'nobounce'):
                suspect.tags['nobounce'] = True
            if self.config.getboolean(self.section, 'noreinject'):
                suspect.tags['noreinject'] = True
            if self.config.getboolean(self.section, 'noappender'):
                suspect.tags['noappender'] = True
            fp = open(self.config.get(self.section, 'debugfile'), 'w')
            suspect.tags['debug'] = True
            suspect.tags['debugfile'] = fp
        self.logger.debug('Debugport: %s , Incoming port: %s' %
                          (debugport, suspect.get_tag('incomingport')))
