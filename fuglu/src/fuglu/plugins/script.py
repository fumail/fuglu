from fuglu.shared import ScannerPlugin, DUNNO, ACCEPT, DELETE, DEFER, REJECT, actioncode_to_string
import os
import traceback
import time
import sys
import runpy


class Stopped(Exception):

    def __init__(self, action, message):
        self.action = action
        self.message = message


class ScriptFilter(ScannerPlugin):

    """This plugin executes scripts found in a specified directory.
This can be used to quickly add a custom filter script without changing the fuglu configuration.

Filterscripts must be written in standard python but with the file ending ``.fgf`` ("fuglu filter")

Scripts are reloaded for every message and executed in alphabetic order. You do not need to restart fuglu to load any changes made to these files.

The API is basically the same as for normal plugins within the ``examine()`` method, with a few special cases:

there is no 'self' which means:

    * access the configuration by using ``config`` directly (instead of ``self.config``)
    * use ``debug('hello world')`` instead of ``self._logger().debug('hello world')``, this will also automatically write to the message debug channel

the script should not return anything, but change the available variables ``action`` and ``message`` instead
(``DUNNO``, ``REJECT``, ``DEFER``, ``ACCEPT``, ``DELETE`` are already imported)

use ``stop(action=DUNNO, message='')`` to exit the script early


Example script:
(put this in /etc/fuglu/scriptfilter/99_demo.fgf for example)

::

    #block all messages from evilsender.example.com
    if not suspect.from_domain=='evilsender.example.com':
        suspect.add_header("x-fuglu-SenderDomain",suspect.from_domain,immediate=True)
        stop()
    debug("hello world")
    action=REJECT
    message="you shall not pass"


    """

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = self._logger()
        self.requiredvars = {
            'scriptdir': {
                'default': '/etc/fuglu/scriptfilter',
                'description': 'Dir that contains the scripts (*.fgf files)',
            }
        }

    def examine(self, suspect):
        scripts = self.get_scripts()
        retaction = DUNNO
        retmessage = ''
        for script in scripts:
            self.logger.debug("Executing script %s" % script)
            suspect.debug("Executing script %s" % script)
            sstart = time.time()
            action, message = self.exec_script(suspect, script)
            send = time.time()
            self.logger.debug("Script %s done in %.4fs result: %s %s" % (
                script, send - sstart, actioncode_to_string(action), message))

            retaction = action
            retmessage = message

            if action != DUNNO:
                break

        return retaction, retmessage

    def lint(self):
        allok = (self.checkConfig() and self.lint_code())
        return allok

    def lint_code(self):
        scriptdir = self.config.get(self.section, 'scriptdir')
        if not os.path.isdir(scriptdir):
            print("Script dir %s does not exist" % scriptdir)
            return False
        scripts = self.get_scripts()
        counter = 0
        for script in scripts:
            counter += 1
            try:
                source = open(script, 'r').read()
                compile(source, script, 'exec')
            except:
                trb = traceback.format_exc()
                print("Script %s failed to compile: %s" % (script, trb))
                return False
        print("%s scripts found" % counter)
        return True

    def _debug(self, suspect, message):
        suspect.debug(message)
        self.logger.debug(message)

    def exec_script(self, suspect, filename):
        action = DUNNO
        message = ''
        debug = lambda message: self._debug(suspect, message)
        info = lambda message: self.logger.info(message)
        warn = lambda message: self.logger.warn(message)

        def stop(action=DUNNO, message=''):
            raise Stopped(action, message)

        scriptenv = dict(
            action=action,
            message=message,
            suspect=suspect,
            debug=debug,
            info=info,
            warn=warn,
            config=self.config,
            stop=stop,
            DUNNO=DUNNO, ACCEPT=ACCEPT, DELETE=DELETE, DEFER=DEFER, REJECT=REJECT,

        )

        try:
            if sys.version_info < (2, 7):
                execfile(filename, scriptenv)
            else:
                scriptenv = runpy.run_path(filename, scriptenv)
                print("script ran through!")
            import pprint
            pprint.pprint(scriptenv)
            action = scriptenv['action']
            message = scriptenv['message']
        except Stopped as stp:
            action = stp.action
            message = stp.message
        except:
            trb = traceback.format_exc()
            self.logger.error("Script %s failed: %s" % (filename, trb))

        return action, message

    def get_scripts(self):
        scriptdir = self.config.get(self.section, 'scriptdir')
        if os.path.isdir(scriptdir):
            filelist = os.listdir(scriptdir)
            scripts = [os.path.join(scriptdir, f)
                       for f in filelist if f.endswith('.fgf')]
            scripts = sorted(scripts)
            return scripts
        else:
            return []
