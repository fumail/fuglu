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

from fuglu.shared import DUNNO, ACCEPT, REJECT, DEFER, DELETE
from fuglu.debug import CrashStore
import logging
from fuglu.stats import Statskeeper
import sys
import traceback
import tempfile
import time
import os
import datetime


class SessionHandler(object):

    """thread handling one message"""

    def __init__(self, protohandler, config, prependers, plugins, appenders):
        self.logger = logging.getLogger("fuglu.SessionHandler")
        self.action = DUNNO
        self.config = config
        self.prependers = prependers
        self.plugins = plugins
        self.appenders = appenders
        self.stats = Statskeeper()
        self.workerthread = None
        self.message = None
        self.protohandler = protohandler

    def set_threadinfo(self, status):
        if self.workerthread != None:
            self.workerthread.threadinfo = status

    def handlesession(self, workerthread=None):
        self.workerthread = workerthread

        starttime = time.time()
        prependheader = self.config.get('main', 'prependaddedheaders')
        try:
            self.set_threadinfo('receiving message')

            self.stats.incount += 1
            suspect = self.protohandler.get_suspect()
            if suspect == None:
                self.logger.error('No Suspect retrieved, ending session')
                return

            if len(suspect.recipients) != 1:
                self.logger.warning('Notice: Message from %s has %s recipients. Plugins supporting only one recipient will see: %s' % (
                    suspect.from_address, len(suspect.recipients), suspect.to_address))
            self.logger.debug("Message from %s to %s: %s bytes stored to %s" % (
                suspect.from_address, suspect.to_address, suspect.size, suspect.tempfile))
            self.set_threadinfo("Handling message %s" % suspect)
            # store incoming port to tag, could be used to disable plugins
            # based on port
            try:
                port = self.protohandler.socket.getsockname()[1]
                if port is not None:
                    suspect.tags['incomingport'] = port
            except Exception as e:
                self.logger.warning('Could not get incoming port: %s' % str(e))

            pluglist = self.run_prependers(suspect)

            starttime = time.time()
            self.run_plugins(suspect, pluglist)

            # Set fuglu spam status if wanted
            if self.config.getboolean('main', 'spamstatusheader'):
                if suspect.is_spam():
                    suspect.addheader("%sSpamstatus" % prependheader, 'YES')
                else:
                    suspect.addheader("%sSpamstatus" % prependheader, 'NO')

            # how long did it all take?
            difftime = time.time() - starttime
            suspect.tags['fuglu.scantime'] = "%.4f" % difftime

            # Debug info to mail
            if self.config.getboolean('main', 'debuginfoheader'):
                debuginfo = str(suspect)
                suspect.addheader("%sDebuginfo" % prependheader, debuginfo)

            # add suspect id for tracking
            if self.config.getboolean('main', 'suspectidheader'):
                suspect.addheader('%sSuspect' % prependheader, suspect.id)

            # checks done.. print out suspect status
            logformat = self.config.get('main', 'logtemplate')
            if logformat.strip() != '':
                self.logger.info(suspect.log_format(logformat))
            suspect.debug(suspect)

            # check if one of the plugins made a decision
            result = self.action

            self.set_threadinfo("Finishing message %s" % suspect)

            message_is_deferred = False
            if result == ACCEPT or result == DUNNO:
                try:
                    self.protohandler.commitback(suspect)
                    self.stats.outcount += 1

                except KeyboardInterrupt:
                    sys.exit()
                except Exception as e:
                    message_is_deferred = True
                    self.logger.error(
                        "Could not commit message. Error: %s" % e)
                    traceback.print_exc(file=sys.stdout)
                    self.protohandler.defer('Internal error trying to commit.')

            elif result == DELETE:
                self.logger.info("MESSAGE DELETED: %s" % suspect.id)
                retmesg = 'OK: (%s)' % suspect.id
                if self.message != None:
                    retmesg = self.message
                self.protohandler.discard(retmesg)
            elif result == REJECT:
                retmesg = "Rejected by content scanner"
                if self.message != None:
                    retmesg = self.message
                self.protohandler.reject(retmesg)
            elif result == DEFER:
                message_is_deferred = True
                retmesg = 'Internal problem - message deferred'
                if self.message != None:
                    retmesg = self.message
                self.protohandler.defer(retmesg)
            else:
                self.logger.error(
                    'Invalid Message action Code: %s. Using DEFER' % result)
                message_is_deferred = True
                self.protohandler.defer('Internal problem - message deferred')

            # run appenders (stats plugin etc) unless msg is deferred
            if not message_is_deferred:
                self.stats.increasecounters(suspect)
                self.run_appenders(suspect, result)
            else:
                self.logger.warning("DEFERRED %s" % suspect.id)

            # clean up
            try:
                os.remove(suspect.tempfile)
                self.logger.debug('Removed tempfile %s' % suspect.tempfile)
            except:
                self.logger.warning(
                    'Could not remove tempfile %s' % suspect.tempfile)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            exc = traceback.format_exc()
            self.logger.error('Exception %s: %s' % (e, exc))
            self.protohandler.defer("internal problem - message deferred")
        self.logger.debug('Session finished')

    def trash(self, suspect, killerplugin=None):
        """copy suspect to trash if this is enabled"""
        trashdir = self.config.get('main', 'trashdir').strip()
        if trashdir == "":
            return

        if not os.path.isdir(trashdir):
            try:
                os.makedirs(trashdir)
            except:
                self.logger.error(
                    "Trashdir %s does not exist and could not be created" % trashdir)
                return
            self.logger.info('Created trashdir %s' % trashdir)

        try:
            (handle, trashfilename) = tempfile.mkstemp(
                prefix=suspect.id, dir=self.config.get('main', 'trashdir'))
            trashfile = os.fdopen(handle, 'w+b')
            trashfile.write(suspect.get_source())
            trashfile.close()
            self.logger.debug('Message stored to trash: %s' % trashfilename)
        except Exception as e:
            self.logger.error(
                "could not create file %s: %s" % (trashfilename, e))

        # TODO: document main.trashlog
        if self.config.has_option('main', 'trashlog') and self.config.getboolean('main', 'trashlog'):
            try:
                handle = open('%s/00-fuglutrash.log' %
                              self.config.get('main', 'trashdir'), 'a')
                # <date> <time> <from address> <to address> <plugin that said "DELETE"> <filename>
                time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                handle.write("%s %s %s %s %s" % (
                    time, suspect.from_address, suspect.to_address, killerplugin, trashfilename))
                handle.write("\n")
                handle.close()
            except Exception as e:
                self.logger.error("Could not update trash log: %s" % e)

    def run_plugins(self, suspect, pluglist):
        """Run scannerplugins on suspect"""
        suspect.debug('Will run plugins: %s' % pluglist)
        for plugin in pluglist:
            try:
                self.logger.debug('Running plugin %s' % plugin)
                self.set_threadinfo(
                    "%s : Running Plugin %s" % (suspect, plugin))
                suspect.debug('Running plugin %s' % str(plugin))
                starttime = time.time()
                ans = plugin.examine(suspect)
                plugintime = time.time() - starttime
                suspect.tags['scantimes'].append((plugin.section, plugintime))
                message = None
                if type(ans) is tuple:
                    result, message = ans
                else:
                    result = ans

                if result == None:
                    result = DUNNO

                suspect.tags['decisions'].append((plugin.section, result))

                if result == DUNNO:
                    suspect.debug('Plugin makes no final decision')
                elif result == ACCEPT:
                    suspect.debug(
                        'Plugin accepts the message - skipping all further tests')
                    self.logger.debug(
                        'Plugin says: ACCEPT. Skipping all other tests')
                    self.action = ACCEPT
                    break
                elif result == DELETE:
                    suspect.debug(
                        'Plugin DELETES this message - no further tests')
                    self.logger.debug(
                        'Plugin says: DELETE. Skipping all other tests')
                    self.action = DELETE
                    self.message = message
                    self.trash(suspect, str(plugin))
                    break
                elif result == REJECT:
                    suspect.debug(
                        'Plugin REJECTS this message - no further tests')
                    self.logger.debug(
                        'Plugin says: REJECT. Skipping all other tests')
                    self.action = REJECT
                    self.message = message
                    break
                elif result == DEFER:
                    suspect.debug(
                        'Plugin DEFERS this message - no further tests')
                    self.logger.debug(
                        'Plugin says: DEFER. Skipping all other tests')
                    self.action = DEFER
                    self.message = message
                    break
                else:
                    self.logger.error(
                        'Invalid Message action Code: %s. Using DUNNO' % result)

            except Exception as e:
                CrashStore.store_exception()
                exc = traceback.format_exc()
                self.logger.error('Plugin %s failed: %s' % (str(plugin), exc))
                suspect.debug(
                    'Plugin failed : %s . Please check fuglu log for more details' % e)

    def run_prependers(self, suspect):
        """Run prependers on suspect"""
        plugcopy = self.plugins[:]
        for plugin in self.prependers:
            try:
                self.logger.debug('Running prepender %s' % plugin)
                self.set_threadinfo(
                    "%s : Running Prepender %s" % (suspect, plugin))
                starttime = time.time()
                result = plugin.pluginlist(suspect, plugcopy)
                plugintime = time.time() - starttime
                suspect.tags['scantimes'].append((plugin.section, plugintime))
                if result != None:
                    plugcopyset = set(plugcopy)
                    resultset = set(result)
                    removed = list(plugcopyset - resultset)
                    added = list(resultset - plugcopyset)
                    if len(removed) > 0:
                        self.logger.debug(
                            'Prepender %s removed plugins: %s' % (plugin, list(map(str, removed))))
                    if len(added) > 0:
                        self.logger.debug(
                            'Prepender %s added plugins: %s' % (plugin, list(map(str, added))))
                    plugcopy = result

            except Exception:
                CrashStore.store_exception()
                exc = traceback.format_exc()
                self.logger.error(
                    'Prepender plugin %s failed: %s' % (str(plugin), exc))
        return plugcopy

    def run_appenders(self, suspect, finaldecision):
        """Run appenders on suspect"""
        if suspect.get_tag('noappenders'):
            return

        for plugin in self.appenders:
            try:
                self.logger.debug('Running appender %s' % plugin)
                suspect.debug('Running appender %s' % plugin)
                self.set_threadinfo(
                    "%s : Running appender %s" % (suspect, plugin))
                starttime = time.time()
                plugin.process(suspect, finaldecision)
                plugintime = time.time() - starttime
                suspect.tags['scantimes'].append((plugin.section, plugintime))
            except Exception:
                CrashStore.store_exception()
                exc = traceback.format_exc()
                self.logger.error(
                    'Appender plugin %s failed: %s' % (str(plugin), exc))
