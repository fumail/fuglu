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
# $Id: archive.py 180 2011-06-16 09:21:16Z gryphius $
#
from fuglu.shared import ScannerPlugin, DELETE


class KillerPlugin(ScannerPlugin):

    """DELETE all mails (for special mail setups like spam traps etc)"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = self._logger()

    def __str__(self):
        return "delete Message"

    def examine(self, suspect):
        return DELETE

    def lint(self):
        print("""!!! WARNING: You have enabled the KILLER plugin - NO message will forwarded to postfix. !!!""")
        return True
