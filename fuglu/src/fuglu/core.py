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

from __future__ import print_function

import re
import os
import sys
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
import datetime
import logging
import threading
from fuglu.threadpool import ThreadPool
import inspect
import traceback
import time
import code
import socket

from fuglu.shared import default_template_values, Suspect, HAVE_BEAUTIFULSOUP, BS_VERSION
from fuglu.connectors.smtpconnector import SMTPServer
from fuglu.connectors.milterconnector import MilterServer
from fuglu.connectors.ncblackholeconnector import NCServer
from fuglu.connectors.esmtpconnector import ESMTPServer

from fuglu.stats import StatsThread
from fuglu.debug import ControlServer, CrashStore
from fuglu import FUGLU_VERSION
from fuglu.funkyconsole import FunkyConsole


def check_version_status(lint=False):
    """Check our version string in DNS for known issues and warn about them

    the lookup should be <7 chars of commitid>.<patch>.<minor>.<major>.versioncheck.fuglu.org
    in case of a release version, use 'release' instead of commit id

    eg, the lookup for 0.6.3 would be:
    release.3.6.0.versioncheck.fuglu.org

    DNS will return NXDOMAIN or 127.0.0.<bitmask>
    2: generic non security related issue
    4: low risk security issue
    8: high risk security issue
    """
    bitmaskmap = {
        2: "there is a known (not security related) issue with this version - consider upgrading",
        4: "there is a known low-risk security issue with this version - an upgrade is recommended",
        8: "there is a known high-risk security issue with this version - upgrade as soon as possible!",
    }

    m = re.match(
        r'^(?P<major>\d{1,4})\.(?P<minor>\d{1,4})\.(?P<patch>\d{1,4})(?:\-(?P<commitno>\d{1,4})\-g(?P<commitid>[a-f0-9]{7}))?$', FUGLU_VERSION)
    if m == None:
        logging.warn("could not parse my version string %s" % FUGLU_VERSION)
        return
    parts = m.groupdict()
    if 'commitid' not in parts or parts['commitid'] == None:
        parts['commitid'] = 'release'

    lookup = "{commitid}.{patch}.{minor}.{major}.versioncheck.fuglu.org".format(
        **parts)
    result = None
    try:
        result = socket.gethostbyname(lookup)
    except:
        # DNS fails happen - try again next time
        pass

    if result == None:
        return

    ret = re.match(r'^127\.0\.0\.(?P<replycode>\d{1,4})$', result)
    if ret != None:
        code = int(ret.groupdict()['replycode'])
        for bitmask, message in bitmaskmap.items():
            if code & bitmask == bitmask:
                logging.warn(message)
                if lint:
                    fc = FunkyConsole()
                    print(fc.strcolor(message, "yellow"))


class MainController(object):

    """main class to startup and control the app"""
    plugins = []
    prependers = []
    appenders = []
    config = None

    def __init__(self, config):
        self.requiredvars = {
            # main section
            'identifier': {
                'section': 'main',
                'description': """identifier can be any string that helps you identifying your config file\nthis helps making sure the correct config is loaded. this identifier will be printed out when fuglu is reloading its config""",
                'default': 'dist',
            },

            'daemonize': {
                'section': 'main',
                'description': "run as a daemon? (fork)",
                'default': "1",
            },

            'user': {
                'section': 'main',
                'description': "run as user",
                'default': "nobody",
            },

            'group': {
                'section': 'main',
                'description': "run as group",
                'default': "nobody",
            },

            'plugindir': {
                'section': 'main',
                'description': "where should fuglu search for additional plugins",
                'default': "",
            },

            'plugins': {
                'section': 'main',
                'description': "what SCANNER plugins do we load, comma separated",
                'default': "archive,attachment,clamav,spamassassin",
            },

            'prependers': {
                'section': 'main',
                'description': "what PREPENDER plugins do we load, comma separated",
                'default': "debug,skip",
            },

            'appenders': {
                'section': 'main',
                'description': "what APPENDER plugins do we load, comma separated\nappender plugins are plugins run after the scanning plugins\nappenders will always be run, even if a a scanner plugin decided to delete/bounce/whatever a message\n(unless a mail is deferred in which case running the appender would not make sense as it will come again)",
                'default': "",
            },

            'bindaddress': {
                'section': 'main',
                'description': "address fuglu should listen on. usually 127.0.0.1 so connections are accepted from local host only",
                'default': "127.0.0.1",
            },

            'incomingport': {
                'section': 'main',
                'description': "incoming port(s) (postfix connects here)\nyou can use multiple comma separated ports here\nf.ex. to separate incoming and outgoing mail and a special port for debugging messages\n10025: standard incoming mail\n10099: outgoing mail\n10888: debug port",
                'default': "10025,10099,10888",
            },

            'outgoinghost': {
                'section': 'main',
                'description': "outgoing hostname/ip where postfix is listening for re-injects.\nuse ${injecthost} to connect back to the IP where the incoming connection came from",
                'default': "127.0.0.1",
            },

            'outgoingport': {
                'section': 'main',
                'description': "outgoing port  where postfix is listening for re-injects)",
                'default': "10026",
            },

            'outgoinghelo': {
                'section': 'main',
                'description': "#outgoing helo we should use for re-injects\nleave empty to auto-detect current hostname",
                'default': "",
            },

            'tempdir': {
                'section': 'main',
                'description': "temp dir where fuglu can store messages while scanning",
                'default': "/tmp",
            },

            'prependaddedheaders': {
                'section': 'main',
                'description': "String to prepend to added headers",
                'default': "X-Fuglu-",
            },

            'trashdir': {
                'section': 'main',
                'description': "If a plugin decides to delete a message, save a copy here\ndefault empty, eg. do not save a backup copy",
                'default': "",
            },

            'trashlog': {
                'section': 'main',
                'description': "list all deleted messages in 00-fuglutrash.log in the trashdir",
                'default': "0",
            },

            'disablebounces': {
                'section': 'main',
                'description': "if this is set to True/1/yes , no Bounces will be sent from Fuglu eg. after a blocked attachment has been detected\nThis may be used for debugging/testing to make sure fuglu can not produce backscatter",
                'default': "0",
            },

            'debuginfoheader': {
                'section': 'main',
                'description': "write debug info header to every mail",
                'default': "0",
            },

            'spamstatusheader': {
                'section': 'main',
                'description': "write a Spamstatus YES/NO header",
                'default': "1",
            },

            'suspectidheader': {
                'section': 'main',
                'description': "write suspect ID to every mail",
                'default': "1",
            },

            'mrtgdir': {
                'section': 'main',
                'description': "write mrtg statistics",
                'default': "",
            },

            'controlport': {
                'section': 'main',
                'description': "port where fuglu provides statistics etc (used by fuglu_control). Can also be a path to a unix socket",
                'default': "/tmp/fuglu_control.sock",
            },

            'logtemplate': {
                'section': 'main',
                'description': "Log pattern to use for all suspects in fuglu log. set empty string to disable logging generic suspect info. Supports the usual template variables plus: ${size}, ${spam} ${highspam}, ${modified} ${decision} ${tags} (short tags representagion) ${fulltags} full tags output, ${decision}",
                'default': 'Suspect ${id} from=${from_address} to=${to_address} size=${size} spam=${spam} virus=${virus} modified=${modified} decision=${decision}',
            },

            'versioncheck': {
                'section': 'main',
                'description': "warn about known severe problems/security issues of current version.\nNote: This performs a DNS lookup of gitrelease.patchlevel.minorversion.majorversion.versioncheck.fuglu.org on startup and fuglu --lint.\nNo other information of any kind is transmitted to outside systems.\nDisable this if you consider the DNS lookup an unwanted information leak.",
                'default': '1',
            },

            # performance section
            'minthreads': {
                'default': "2",
                'section': 'performance',
                'description': 'minimum scanner threads',
            },
            'maxthreads': {
                'default': "40",
                'section': 'performance',
                'description': 'maximum scanner threads',
            },


            # spam section
            'defaultlowspamaction': {
                'default': "DUNNO",
                'section': 'spam',
                'description': """what to do with messages that plugins think are spam but  not so sure  ("low spam")\nin normal usage you probably never set this something other than DUNNO\nthis is a DEFAULT action, eg. anti spam plugins should take this if you didn't set \n a individual override""",
            },

            'defaulthighspamaction': {
                'default': "DUNNO",
                'section': 'spam',
                'description': """what to do with messages if a plugin is sure it is spam ("high spam") \nin after-queue mode this is probably still DUNNO or maybe DELETE for courageous people\nthis is a DEFAULT action, eg. anti spam plugins should take this if you didn't set\n a individual override """,
            },

            # virus section
            'defaultvirusaction': {
                'default': "DELETE",
                'section': 'virus',
                'description': """#what to do with messages if a plugin detects a virus\nin after-queue mode this should probably be DELETE\nin pre-queue mode you could use REJECT\nthis is a DEFAULT action, eg. anti-virus plugins should take this if you didn't set \n a individual override""",
            },

            # smtpconnector
            'requeuetemplate': {
                'default': "FUGLU REQUEUE(${id}): ${injectanswer}",
                'section': 'smtpconnector',
                'description': """confirmation template sent back to the connecting postfix for accepted messages""",
            },

            # esmtpconnector
            'queuetemplate': {
                'default': "${injectanswer}",
                'section': 'esmtpconnector',
                'description': """confirmation template sent back to the connecting client for accepted messages""",
            },

            # databaseconfig
            'dbconnectstring': {
                'default': "",
                'section': 'databaseconfig',
                'description': """read runtime configuration values from a database. requires sqlalchemy to be installed""",
                'confidential': True,
            },

            'sql': {
                'default': """SELECT value FROM fugluconfig WHERE `section`=:section AND `option`=:option AND `scope` IN ('$GLOBAL',CONCAT('%',:to_domain),:to_address) ORDER BY `scope` DESC""",
                'section': 'databaseconfig',
                'description': """sql query that returns a configuration value override. sql placeholders are ':section',':option' in addition the usual suspect filter default values like ':to_domain', ':to_address' etc\nif the statement returns more than one row/value only the first value in the first row is used""",
            },

            # environment
            'boundarydistance': {
                'default': "0",
                'section': 'environment',
                'description': """Distance to the boundary MTA ("how many received headers should fuglu skip to determine the last untrusted host information"). Only required if plugins need to have information about the last untrusted host(SPFPlugin)""",
            },
            'trustedhostsregex': {
                'default': "",
                'section': 'environment',
                'description': """Optional regex that should be applied to received headers to skip trusted (local) mta helo/ip/reverse dns.\nOnly required if plugins need to have information about the last untrusted host and the message doesn't pass a fixed amount of hops to reach this system in your network""",
            },

            #  plugin alias
            'debug': {
                'default': "fuglu.plugins.p_debug.MessageDebugger",
                'section': 'PluginAlias',
            },

            'skip': {
                'default': "fuglu.plugins.p_skipper.PluginSkipper",
                'section': 'PluginAlias',
            },

            'fraction': {
                'default': "fuglu.plugins.p_fraction.PluginFraction",
                'section': 'PluginAlias',
            },

            'archive': {
                'default': "fuglu.plugins.archive.ArchivePlugin",
                'section': 'PluginAlias',
            },

            'attachment': {
                'default': "fuglu.plugins.attachment.FiletypePlugin",
                'section': 'PluginAlias',
            },

            'clamav': {
                'default': "fuglu.plugins.clamav.ClamavPlugin",
                'section': 'PluginAlias',
            },

            'spamassassin': {
                'default': "fuglu.plugins.sa.SAPlugin",
                'section': 'PluginAlias',
            },

            'vacation': {
                'default': "fuglu.plugins.vacation.VacationPlugin",
                'section': 'PluginAlias',
            },

            'actionoverride': {
                'default': "fuglu.plugins.actionoverride.ActionOverridePlugin",
                'section': 'PluginAlias',
            },

            'icap': {
                'default': "fuglu.plugins.icap.ICAPPlugin",
                'section': 'PluginAlias',
            },

            'sssp': {
                'default': "fuglu.plugins.sssp.SSSPPlugin",
                'section': 'PluginAlias',
            },

            'fprot': {
                'default': "fuglu.plugins.fprot.FprotPlugin",
                'section': 'PluginAlias',
            },

            'scriptfilter': {
                'default': "fuglu.plugins.script.ScriptFilter",
                'section': 'PluginAlias',
            },

            'dkimsign': {
                'default': "fuglu.plugins.domainauth.DKIMSignPlugin",
                'section': 'PluginAlias',
            },

            'dkimverify': {
                'default': "fuglu.plugins.domainauth.DKIMVerifyPlugin",
                'section': 'PluginAlias',
            },

            'spf': {
                'default': "fuglu.plugins.domainauth.SPFPlugin",
                'section': 'PluginAlias',
            },
        }

        self.config = config
        self.servers = []
        self.logger = self._logger()
        self.stayalive = True
        self.threadpool = None
        self.controlserver = None
        self.started = datetime.datetime.now()
        self.statsthread = None
        self.debugconsole = False

    def _logger(self):
        myclass = self.__class__.__name__
        loggername = "fuglu.%s" % (myclass,)
        return logging.getLogger(loggername)

    def start_connector(self, portspec):
        port = portspec.strip()
        protocol = 'smtp'

        if port.find(':') > 0:
            (protocol, port) = port.split(':')

        self.logger.info("starting connector %s/%s" % (protocol, port))
        try:
            port = int(port)
            if protocol == 'smtp':
                smtpserver = SMTPServer(
                    self, port=port, address=self.config.get('main', 'bindaddress'))
                tr = threading.Thread(target=smtpserver.serve, args=())
                tr.daemon = True
                tr.start()
                self.servers.append(smtpserver)
            elif protocol == 'esmtp':
                esmtpserver = ESMTPServer(
                    self, port=port, address=self.config.get('main', 'bindaddress'))
                tr = threading.Thread(target=esmtpserver.serve, args=())
                tr.daemon = True
                tr.start()
                self.servers.append(esmtpserver)
            elif protocol == 'milter':
                milterserver = MilterServer(
                    self, port=port, address=self.config.get('main', 'bindaddress'))
                tr = threading.Thread(target=milterserver.serve, args=())
                tr.daemon = True
                tr.start()
                self.servers.append(milterserver)
            elif protocol == 'netcat':
                ncserver = NCServer(
                    self, port=port, address=self.config.get('main', 'bindaddress'))
                tr = threading.Thread(target=ncserver.serve, args=())
                tr.daemon = True
                tr.start()
                self.servers.append(ncserver)
            else:
                self.logger.error(
                    'Unknown Interface Protocol: %s, ignoring server on port %s' % (protocol, port))
        except Exception as e:
            self.logger.error(
                "could not start connector %s/%s : %s" % (protocol, port, str(e)))

    def startup(self):
        self.load_extensions()
        ok = self.load_plugins()
        if not ok:
            sys.stderr.write(
                "Some plugins failed to load, please check the logs. Aborting.\n")
            self.logger.info('Fuglu shut down after fatal error condition')
            sys.exit(1)
        self.logger.info("Init Stat Engine")
        self.statsthread = StatsThread(self.config)
        mrtg_stats_thread = threading.Thread(
            name='MRTG-Statswriter', target=self.statsthread.writestats, args=())
        mrtg_stats_thread.daemon = True
        mrtg_stats_thread.start()

        self.logger.info("Init Threadpool")
        try:
            minthreads = self.config.getint('performance', 'minthreads')
            maxthreads = self.config.getint('performance', 'maxthreads')
        except configparser.NoSectionError:
            self.logger.warning(
                'Performance section not configured, using default thread numbers')
            minthreads = 1
            maxthreads = 3

        queuesize = maxthreads * 10
        self.threadpool = ThreadPool(minthreads, maxthreads, queuesize)

        self.logger.info("Starting interface sockets...")
        ports = self.config.get('main', 'incomingport')
        for port in ports.split(','):
            self.start_connector(port)

        # control socket
        control = ControlServer(self, address=self.config.get(
            'main', 'bindaddress'), port=self.config.get('main', 'controlport'))
        ctrl_server_thread = threading.Thread(
            name='Control server', target=control.serve, args=())
        ctrl_server_thread.daemon = True
        ctrl_server_thread.start()

        self.controlserver = control

        self.logger.info('Startup complete')
        if self.debugconsole:
            self.run_debugconsole()
        else:
            if self.config.getboolean('main', 'versioncheck'):
                # log possible issues with this version
                check_version_status()

            # mainthread dummy loop
            while self.stayalive:
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    self.stayalive = False
        self.shutdown()

    def run_debugconsole(self):
        from fuglu.shared import DUNNO, ACCEPT, DELETE, REJECT, DEFER, Suspect

        # do not import readline at the top, it will cause undesired output, for example when generating the default config
        # http://stackoverflow.com/questions/15760712/python-readline-module-prints-escape-character-during-import
        import readline

        print("Fuglu Interactive Console started")
        print("")
        print("pre-defined locals:")

        mc = self
        print("mc : maincontroller")

        terp = code.InteractiveConsole(locals())
        terp.interact("")

    def run_netconsole(self, port=1337, bind="0.0.0.0"):
        """start a network console"""
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        serversocket = socket.socket()
        serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serversocket.bind((bind, port))
        serversocket.listen(1)
        clientsocket, address = serversocket.accept()  # client socket
        self.logger.info("Interactive python connection from %s/%s" % address)

        class sw:  # socket wrapper

            def __init__(self, s):
                self.s = s

            def read(self, length):
                return self.s.recv(length)

            def write(self, st):
                return self.s.send(st)

            def readline(self):
                return self.read(256)
        sw = sw(clientsocket)
        sys.stdin = sw
        sys.stdout = sw
        sys.stderr = sw
        mc = self
        terp = code.InteractiveConsole(locals())
        try:
            terp.interact(
                "Fuglu Python Shell - MainController available as 'mc'")
        except:
            pass
        self.logger.info(
            "done talking to %s - closing interactive shell on %s/%s" % (address[0], bind, port))
        sys.stdin = old_stdin
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        try:
            clientsocket.close()
        except Exception as e:
            self.logger.warning(
                "Failed to close shell client socket: %s" % str(e))
        try:
            serversocket.close()
        except Exception as e:
            self.logger.warning(
                "Failed to close shell server socket: %s" % str(e))

    def reload(self):
        """apply config changes"""
        self.logger.info('Applying configuration changes...')

        # threadpool changes?
        minthreads = self.config.getint('performance', 'minthreads')
        maxthreads = self.config.getint('performance', 'maxthreads')

        if self.threadpool.minthreads != minthreads or self.threadpool.maxthreads != maxthreads:
            self.logger.info(
                'Threadpool config changed, initialising new threadpool')
            queuesize = maxthreads * 10
            currentthreadpool = self.threadpool
            self.threadpool = ThreadPool(minthreads, maxthreads, queuesize)
            currentthreadpool.stayalive = False

        # smtp engine changes?
        ports = self.config.get('main', 'incomingport')
        portspeclist = ports.split(',')
        portlist = []

        for portspec in portspeclist:
            if portspec.find(':') > 0:
                (protocol, port) = portspec.split(':')
                port = int(port)
            else:
                port = int(portspec)
            portlist.append(port)
            alreadyRunning = False
            for serv in self.servers:
                if serv.port == port:
                    alreadyRunning = True
                    break

            if not alreadyRunning:
                self.start_connector(portspec)

        servercopy = self.servers[:]
        for serv in servercopy:
            if serv.port not in portlist:
                self.logger.info(
                    'Closing server socket on port %s' % serv.port)
                serv.shutdown()
                self.servers.remove(serv)

        self.logger.info('Config changes applied')

    def shutdown(self):
        self.statsthread.stayalive = False
        for server in self.servers:
            self.logger.info('Closing server socket on port %s' % server.port)
            server.shutdown()

        if self.controlserver != None:
            self.controlserver.shutdown()

        self.threadpool.stayalive = False
        self.stayalive = False
        self.logger.info('Shutdown complete')
        self.logger.info('Remaining threads: %s' % threading.enumerate())

    def _lint_dependencies(self, fc):
        print(fc.strcolor('Checking dependencies...', 'magenta'))
        try:
            import sqlalchemy
            print(fc.strcolor('sqlalchemy: installed', 'green'))
        except:
            print(fc.strcolor('sqlalchemy: not installed', 'yellow') +
                  " Optional dependency, required if you want to enable any database lookups")

        if HAVE_BEAUTIFULSOUP:
            print(
                fc.strcolor('BeautifulSoup: V%s installed' % BS_VERSION, 'green'))
        else:
            print(fc.strcolor('BeautifulSoup: not installed', 'yellow') +
                  " Optional dependency, this improves accuracy for stripped body searches in filters - not required with a default config")

        try:
            import magic

            if hasattr(magic, 'open'):
                magic_vers = "python-file/libmagic bindings (http://www.darwinsys.com/file/)"
                print(fc.strcolor('magic: found %s' % magic_vers, 'green'))
            elif hasattr(magic, 'from_buffer'):
                magic_vers = "python-magic (https://github.com/ahupp/python-magic)"
                print(fc.strcolor('magic: found %s' % magic_vers, 'green'))
            else:
                print(fc.strcolor('magic: unsupported version', 'yellow') +
                      " File type detection requires either the python bindings from http://www.darwinsys.com/file/ or python magic from https://github.com/ahupp/python-magic")
        except:
            print(fc.strcolor('magic: not installed', 'yellow') +
                  " Optional dependency, without python-file or python-magic the attachment plugin's automatic file type detection will easily be fooled")

    def lint(self):
        errors = 0
        fc = FunkyConsole()
        self._lint_dependencies(fc)

        print(fc.strcolor('Loading extensions...', 'magenta'))
        exts = self.load_extensions()
        for ext in exts:
            (name, enabled, status) = ext
            pname = fc.strcolor(name, 'cyan')
            if enabled:
                penabled = fc.strcolor('enabled', 'green')
            else:
                penabled = fc.strcolor('disabled', 'red')
            print("%s: %s (%s)" % (pname, penabled, status))

        print(fc.strcolor('Loading plugins...', 'magenta'))
        if not self.load_plugins():
            print(fc.strcolor('At least one plugin failed to load', 'red'))
        print(fc.strcolor('Plugin loading complete', 'magenta'))

        print("Linting ", fc.strcolor("main configuration", 'cyan'))
        if not self.checkConfig():
            print(fc.strcolor("ERROR", "red"))
        else:
            print(fc.strcolor("OK", "green"))

        trashdir = self.config.get('main', 'trashdir').strip()
        if trashdir != "":
            if not os.path.isdir(trashdir):
                print(
                    fc.strcolor("Trashdir %s does not exist" % trashdir, 'red'))

        # sql config override
        sqlconfigdbconnectstring = self.config.get(
            'databaseconfig', 'dbconnectstring')
        if sqlconfigdbconnectstring.strip() != '':
            print("")
            print("Linting ", fc.strcolor("sql configuration", 'cyan'))
            try:
                from fuglu.extensions.sql import get_session
                sess = get_session(sqlconfigdbconnectstring)
                tempsuspect = Suspect(
                    'sender@example.com', 'recipient@example.com', '/dev/null')
                sqlvars = dict(
                    section='testsection', option='testoption', scope='$GLOBAL')
                default_template_values(tempsuspect, sqlvars)
                sess.execute(self.config.get('databaseconfig', 'sql'), sqlvars)
                sess.remove()
                print(fc.strcolor("OK", 'green'))
            except Exception as e:
                print(fc.strcolor("Failed %s" % str(e), 'red'))

        allplugins = self.plugins + self.prependers + self.appenders

        for plugin in allplugins:
            print()
            print("Linting Plugin ", fc.strcolor(str(plugin), 'cyan'),
                  'Config section:', fc.strcolor(str(plugin.section), 'cyan'))
            try:
                result = plugin.lint()
            except Exception as e:
                CrashStore.store_exception()
                print("ERROR: %s" % e)
                result = False

            if result:
                print(fc.strcolor("OK", "green"))
            else:
                errors = errors + 1
                print(fc.strcolor("ERROR", "red"))
        print("%s plugins reported errors." % errors)

        if self.config.getboolean('main', 'versioncheck'):
            check_version_status(lint=True)

    def propagate_defaults(self, requiredvars, config, defaultsection=None):
        """propagate defaults from requiredvars if they are missing in config"""
        for option, infodic in requiredvars.items():
            if 'section' in infodic:
                section = infodic['section']
            else:
                section = defaultsection

            default = infodic['default']

            if not config.has_section(section):
                config.add_section(section)

            if not config.has_option(section, option):
                config.set(section, option, default)

    def propagate_core_defaults(self):
        """check for missing core config options and try to fill them with defaults
        must be called before we can do plugin loading stuff
        """
        self.propagate_defaults(self.requiredvars, self.config, 'main')

    def propagate_plugin_defaults(self):
        """propagate defaults from loaded lugins"""
        #plugins, prependers, appenders
        allplugs = self.plugins + self.prependers + self.appenders
        for plug in allplugs:
            if hasattr(plug, 'requiredvars'):
                requiredvars = getattr(plug, 'requiredvars')
                if type(requiredvars) == dict:
                    self.propagate_defaults(
                        requiredvars, self.config, plug.section)

    def checkConfig(self):
        """Check if all requred options are in the config file
        Fill missing values with defaults if possible
        """
        allOK = True
        for config, infodic in self.requiredvars.items():
            section = infodic['section']
            try:
                var = self.config.get(section, config)

                if 'validator' in infodic:
                    if not infodic["validator"](var):
                        print(
                            "Validation failed for [%s] :: %s" % (section, config))
                        allOK = False

            except configparser.NoSectionError:
                print(
                    "Missing configuration section [%s] :: %s" % (section, config))
                allOK = False
            except configparser.NoOptionError:
                print(
                    "Missing configuration value [%s] :: %s" % (section, config))
                allOK = False
        return allOK

    def load_extensions(self):
        """load fuglu extensions"""
        ret = []
        import fuglu.extensions
        for extension in fuglu.extensions.__all__:
            mod = __import__('fuglu.extensions.%s' % extension)
            ext = getattr(mod, 'extensions')
            fl = getattr(ext, extension)
            enabled = getattr(fl, 'ENABLED')
            status = getattr(fl, 'STATUS')
            name = getattr(fl, '__name__')
            ret.append((name, enabled, status))
        return ret

    def get_component_by_alias(self, pluginalias):
        """Returns the full plugin component from an alias. if this alias is not configured, return the original string"""
        if not self.config.has_section('PluginAlias'):
            return pluginalias

        if not self.config.has_option('PluginAlias', pluginalias):
            return pluginalias

        return self.config.get('PluginAlias', pluginalias)

    def load_plugins(self):
        """load plugins defined in config"""
        allOK = True
        plugdir = self.config.get('main', 'plugindir').strip()
        if plugdir != "" and not os.path.isdir(plugdir):
            self._logger().warning('Plugin directory %s not found' % plugdir)

        if plugdir != "":
            self._logger().debug(
                'Searching for additional plugins in %s' % plugdir)
            if plugdir not in sys.path:
                sys.path.insert(0, plugdir)

        self._logger().debug('Module search path %s' % sys.path)
        self._logger().debug('Loading scanner plugins')
        newplugins, loadok = self._load_all(self.config.get('main', 'plugins'))
        if not loadok:
            allOK = False

        newprependers, loadok = self._load_all(
            self.config.get('main', 'prependers'))
        if not loadok:
            allOK = False

        newappenders, loadok = self._load_all(
            self.config.get('main', 'appenders'))
        if not loadok:
            allOK = False

        if allOK:
            self.plugins = newplugins
            self.prependers = newprependers
            self.appenders = newappenders
            self.propagate_plugin_defaults()

        return allOK

    def _load_all(self, configstring):
        """load all plugins from config string. returns tuple ([list of loaded instances],allOk)"""
        pluglist = []
        config_re = re.compile(
            """^(?P<structured_name>[a-zA-Z0-9\.\_\-]+)(?:\((?P<config_override>[a-zA-Z0-9\.\_\-]+)\))?$""")
        allOK = True
        plugins = configstring.split(',')
        for plug in plugins:
            if plug == "":
                continue
            m = config_re.match(plug)
            if m == None:
                self.logger.error('Invalid Plugin Syntax: %s' % plug)
                allOK = False
                continue
            structured_name, configoverride = m.groups()
            structured_name = self.get_component_by_alias(structured_name)
            try:
                plugininstance = self._load_component(
                    structured_name, configsection=configoverride)
                pluglist.append(plugininstance)
            except (configparser.NoSectionError, configparser.NoOptionError):
                CrashStore.store_exception()
                self._logger().error(
                    "The plugin %s is accessing the config in __init__ -> can not load default values" % structured_name)
            except Exception as e:
                CrashStore.store_exception()
                self._logger().error('Could not load plugin %s : %s' %
                                     (structured_name, e))
                exc = traceback.format_exc()
                self._logger().error(exc)
                allOK = False

        return pluglist, allOK

    def _load_component(self, structured_name, configsection=None):
        # from:
        # http://mail.python.org/pipermail/python-list/2003-May/204392.html
        component_names = structured_name.split('.')
        mod = __import__('.'.join(component_names[:-1]))
        for component_name in component_names[1:]:
            mod = getattr(mod, component_name)

        if configsection == None:
            plugininstance = mod(self.config)
        else:
            # check if plugin supports config override
            if 'section' in inspect.getargspec(mod.__init__)[0]:
                plugininstance = mod(self.config, section=configsection)
            else:
                raise Exception('Cannot set Config Section %s : Plugin %s does not support config override' % (
                    configsection, mod))
        return plugininstance
