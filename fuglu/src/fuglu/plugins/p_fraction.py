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

from fuglu.shared import PrependerPlugin, SuspectFilter
import os


class PluginFraction(PrependerPlugin):

    """Runs only a fraction of loaded scanner plugins based on standard filter file
Use this if you only want to run a fraction of the standard plugins on a specific port for example
eg. put this in /etc/fuglu/pluginfraction.regex:

@incomingport    1100    SAPlugin,AttachmentPlugin
"""

    def __init__(self, config, section=None):
        PrependerPlugin.__init__(self, config, section)
        self.filter = None
        self.requiredvars = {
            'filterfile': {
                'default': '/etc/fuglu/pluginfraction.regex',
            }
        }
        self.logger = self._logger()

    def __str__(self):
        return "Plugin Fraction"

    def pluginlist(self, suspect, pluginlist):
        """Removes scannerplugins based on filter file"""
        if not self._initfilter():
            return None

        args = self.filter.get_args(suspect)
        # each arg should be a comma separated list of classnames to skip

        if len(args) == 0:
            return None
        includepluginlist = []

        for arg in args:
            includepluginlist.extend(arg.split(','))

        listcopy = pluginlist[:]
        for plug in pluginlist:
            name = plug.__class__.__name__
            if name not in includepluginlist:
                listcopy.remove(plug)
        return listcopy

    def _initfilter(self):
        if self.filter != None:
            return True

        filename = self.config.get(self.section, 'filterfile')
        if filename == None or filename == "":
            return False

        if not os.path.exists(filename):
            self.logger.error(
                'Filterfile not found for pluginfraction: %s' % filename)
            return False

        self.filter = SuspectFilter(filename)
        return True

    def lint(self):
        return (self.checkConfig() and self.lint_filter())

    def lint_filter(self):
        filterfile = self.config.get(self.section, 'filterfile')
        filter = SuspectFilter(filterfile)
        return filter.lint()
