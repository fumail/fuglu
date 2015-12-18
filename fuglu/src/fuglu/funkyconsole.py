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


class FunkyConsole:

    """Totally useless console colors for the lint mode"""

    def __init__(self):
        self.BG = {}
        self.BG["black"] = "40"
        self.BG["red"] = "41"
        self.BG["green"] = "4"
        self.BG["brown"] = "43"
        self.BG["blue"] = "44"
        self.BG["magenta"] = "45"
        self.BG["cyan"] = "46"
        self.BG["white"] = "47"

        self.RESET = "\x1b[0m"

        self.MODE = {}
        self.MODE["default"] = "0"
        self.MODE["bold"] = "1"
        self.MODE["blink"] = "5"
        self.MODE["noblink"] = "25"

        self.FG = {}
        self.FG["white"] = "00"
        self.FG["black"] = "30"
        self.FG["red"] = "31"
        self.FG["green"] = "32"
        self.FG["brown"] = "33"
        self.FG["blue"] = "34"
        self.FG["magenta"] = "35"
        self.FG["cyan"] = "36"
        self.FG["gray"] = "37"
        # shortcuts
        self.FG["yellow"] = self.FG["brown"] + ";" + self.MODE["bold"]

    def strcolor(self, content, commandlist, resetAfter=True):
        """returns the content encapsulated in the escapesequences to print coloured output"""
        if type(commandlist) is str:
            commandlist = (self.FG[commandlist],)
        esc = self._buildescape(commandlist)
        ret = esc + str(content)
        if resetAfter:
            ret = ret + self.RESET
        return ret

    def _buildescape(self, commandlist):
        """builds escape sequences"""
        escseq = "\x1b["
        for cmd in commandlist:
            if cmd != None:
                escseq = escseq + cmd + ";"
        escseq = escseq[0:-1]  # strip last ;
        escseq = escseq + "m"
        return escseq
