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
Example scanner plugin
"""

from fuglu.shared import ScannerPlugin, DUNNO


class HelloWorld(ScannerPlugin):

    """Basic example scanner plugin which just writes a greeting message to the log for every incoming message"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {  # this defines the configuration options for a plugin
            'greeting': {  # name of the config
                # default value, always use strings here
                'default': 'hello world!',
                # included as comment when generating default config files
                'description': 'greeting message the plugin should log to the console',
            }
        }
        # DO NOT call self.config.get .. here!

    def __str__(self):
        """return short human readable name here"""
        return "Hello World Greeter"

    def examine(self, suspect):
        """This is the most important function you have to implement in scanner plugins"""

        # read config example
        greeting = self.config.get(self.section, 'greeting')

        # debug info is helpful when the message is run through fuglu_debug
        suspect.debug("Greeting: %s" % greeting)

        # log example
        self._logger().info("%s greets %s: %s" %
                            (suspect.from_address, suspect.to_address, greeting))

        # header access example
        msgrep = suspect.get_message_rep()
        if "From" in msgrep:
            self._logger().info("Message from: %s" % msgrep['From'])
        else:
            self._logger().warning("Message has no 'From' header!")

        # plugins should return one of the action codes: DUNNO (default), REJECT, DEFER, ACCEPT  - imported from fuglu.shared
        # you can also return a message, for example:
        # return DEFER, "please try again later"
        return DUNNO
