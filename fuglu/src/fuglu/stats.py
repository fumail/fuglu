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

import time
import threading
import logging
import os


class Statskeeper(object):

    """Keeps track of a few stats to generate mrtg graphs and stuff"""
    __shared_state = {}

    def __init__(self):
        self.__dict__ = self.__shared_state
        if not hasattr(self, 'totalcount'):
            self.totalcount = 0
            self.spamcount = 0
            self.hamcount = 0
            self.viruscount = 0
            self.incount = 0
            self.outcount = 0
            self.scantimes = []
            self.starttime = time.time()
            self.lastscan = 0

    def uptime(self):
        """uptime since we started fuglu"""
        total_seconds = time.time() - self.starttime
        MINUTE = 60
        HOUR = MINUTE * 60
        DAY = HOUR * 24
        # Get the days, hours, etc:
        days = int(total_seconds / DAY)
        hours = int((total_seconds % DAY) / HOUR)
        minutes = int((total_seconds % HOUR) / MINUTE)
        seconds = int(total_seconds % MINUTE)
        # Build up the pretty string (like this: "N days, N hours, N minutes, N
        # seconds")
        string = ""
        if days > 0:
            string += str(days) + " " + (days == 1 and "day" or "days") + ", "
        if len(string) > 0 or hours > 0:
            string += str(hours) + " " + \
                (hours == 1 and "hour" or "hours") + ", "
        if len(string) > 0 or minutes > 0:
            string += str(minutes) + " " + \
                (minutes == 1 and "minute" or "minutes") + ", "
        string += str(seconds) + " " + (seconds == 1 and "second" or "seconds")
        return string

    def numthreads(self):
        """return the number of threads"""
        return len(threading.enumerate())

    def increasecounters(self, suspect):
        """Update local counters after a suspect has passed the system"""
        self.totalcount += 1
        isspam = suspect.is_spam()
        isvirus = suspect.is_virus()

        if isspam:
            self.spamcount += 1

        if isvirus:
            self.viruscount += 1

        if not (isspam or isvirus):
            self.hamcount += 1

        scantime = suspect.get_tag('fuglu.scantime')
        self._appendscantime(scantime)
        self.lastscan = time.time()

    def scantime(self):
        """Get the average scantime of the last 100 messages.
        If last msg is older than five minutes, return 0"""
        tms = self.scantimes[:]
        length = len(tms)

        # no entries in scantime list
        if length == 0:
            return "0"

        # newest entry is older than five minutes
        # clear entries
        if time.time() - self.lastscan > 300:
            self.scantimes = []
            return "0"

        avg = sum(tms) / length
        avgstring = "%.4f" % avg
        return avgstring

    def _appendscantime(self, scantime):
        """add new entry to the list of scantimes"""
        try:
            f = float(scantime)
        except:
            return
        while len(self.scantimes) > 100:
            del self.scantimes[0]

        self.scantimes.append(f)


class StatsThread(object):

    """Keep Track of statistics and write mrtg data"""

    def __init__(self, config):
        self.config = config
        self.stats = Statskeeper()
        self.logger = logging.getLogger('fuglu.stats')
        self.writeinterval = 30
        self.identifier = 'FuGLU'
        self.stayalive = True

    def writestats(self):
        dir = self.config.get('main', 'mrtgdir')
        if dir == None or dir.strip() == "":
            self.logger.debug(
                'No mrtg directory defined, disabling stats writer')
            return

        if not os.path.isdir(dir):
            self.logger.error(
                'MRTG directory %s not found, disabling stats writer' % dir)
            return

        self.logger.info('Writing statistics to %s' % dir)

        while self.stayalive:
            time.sleep(self.writeinterval)
            uptime = self.stats.uptime()

            # total messages
            self.write_mrtg('%s/inout' % dir, float(self.stats.incount),
                            float(self.stats.outcount), uptime, self.identifier)
            # spam ham
            self.write_mrtg('%s/hamspam' % dir, float(self.stats.hamcount),
                            float(self.stats.spamcount), uptime, self.identifier)

            # num threads
            self.write_mrtg(
                '%s/threads' % dir, self.stats.numthreads(), None, uptime, self.identifier)

            # virus
            self.write_mrtg(
                '%s/virus' % dir, float(self.stats.viruscount), None, uptime, self.identifier)

            # scan time
            self.write_mrtg(
                '%s/scantime' % dir, self.stats.scantime(), None, uptime, self.identifier)

    def write_mrtg(self, filename, value1, value2, uptime, identifier):
        try:
            fp = open(filename, 'w')
            fp.write("%s\n" % value1)
            if value2:
                fp.write("%s\n" % value2)
            else:
                fp.write("0\n")
            fp.write("%s\n%s\n" % (uptime, identifier))
            fp.close()
        except Exception as e:
            self.logger.error(
                'Could not write mrtg stats file %s : %s)' % (filename, e))
