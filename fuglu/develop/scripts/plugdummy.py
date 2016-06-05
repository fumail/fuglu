#!/usr/bin/python
# run a plugin with a dummy suspect without a running fuglu daemon

import optparse
import sys
import logging
import tempfile
import os
import email

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

try:
    from email.message import Message
except ImportError:
    from email import Message

try:
    from email.header import Header
except ImportError:
    from email import Header
try:
    from email.mime.text import MIMEText
except ImportError:
    from email.MIMEText import MIMEText

try:
    from email.utils import formatdate
except ImportError:
    from email.Utils import formatdate

from fuglu.shared import Suspect, ScannerPlugin, DUNNO, actioncode_to_string,\
    AppenderPlugin, PrependerPlugin
from fuglu.core import MainController


def run_debugconsole(**kwargs):
    import readline
    import code
    from fuglu.shared import DUNNO, ACCEPT, DELETE, REJECT, DEFER, Suspect
    print("Fuglu Interactive Console started")
    print("")
    print("pre-defined locals:")
    print(kwargs)
    print("")

    available = locals()
    available.update(kwargs)

    terp = code.InteractiveConsole(available)
    terp.interact("")

if __name__ == '__main__':

    parser = optparse.OptionParser(add_help_option=False)
    parser.add_option("-s", action="store", dest="sender",
                      default="sender@fuglu.local", help="envelope sender")
    parser.add_option(
        "-r", action="append", dest="recipients", help="add envelope recipient")
    parser.add_option(
        "-h", action="append", dest="headers", help="add header, format: name:value")
    parser.add_option(
        "-t", action="append", dest="tags", help="set tag, format: name:value")
    parser.add_option("-b", "--body", action="store",
                      dest="body", help="Body content (or path to textfile)")
    parser.add_option("-e", "--eml", action="store", dest="eml",
                      help="use eml content as message file. if this is enabled, body is ignored")
    parser.add_option("-d", "--defaultconfig", action="store_true", default=False,
                      dest="defaultconfig", help="print plugin default config and exit")
    parser.add_option("-o", "--option", action="append", dest="config",
                      help="set config option format: [section]option:value  ([section] is optional, uses plugins name by default")
    parser.add_option(
        "-p", "--plugindir", action="append", dest="plugindirs", help="plugindir(s)")
    parser.add_option("-c", action="store_true", dest="console", default=False,
                      help="start an interactive console after the plugin has been run")
    parser.add_option(
        "--help", action="store_true", dest="help", default=False, help="show options")
    parser.add_option("-l", action="store_true", dest="lint",
                      default=False, help="run lint instead of examine/process")
    (opts, args) = parser.parse_args()
    if opts.help:
        print(parser.format_help().strip())
        sys.exit(0)
    # start with INFO, so we don't have fuglus internal debug noise
    logging.basicConfig(level=logging.INFO)

    if len(args) < 1:
        print("usage: plugdummy.py [options] [plugin] [plugin...]")
        sys.exit(1)
    pluginlist = args

    for plugindir in opts.plugindirs:
        if plugindir not in sys.path:
            sys.path.insert(0, plugindir)

    # prepare config
    config = ConfigParser()
    config.add_section('main')

    prependers = []
    scanners = []
    appenders = []

    # autodetect plugin type
    tempmc = MainController(config)
    for plugin in pluginlist:
        try:
            pluginstance = tempmc._load_component(plugin)
        except Exception as e:
            print("Could not load plugin %s: %s" % (plugin, str(e)))
            sys.exit(1)

        if isinstance(pluginstance, ScannerPlugin):
            scanners.append(plugin)
        elif isinstance(pluginstance, PrependerPlugin):
            prependers.append(plugin)
        elif isinstance(pluginstance, AppenderPlugin):
            appenders.append(plugin)
        else:
            print("%s doesn't seem to be a fuglu plugin - ignoring" % plugin)

    config.set('main', 'plugins', ','.join(scanners))
    config.set('main', 'appenders', ','.join(appenders))
    config.set('main', 'prependers', ','.join(prependers))

    # load plugin
    mc = MainController(config)
    mc.propagate_core_defaults()

    mc.load_extensions()
    ok = mc.load_plugins()
    if not ok:
        logging.error("Could not load plugin(s)")
        sys.exit(1)

    if opts.defaultconfig:
        sec = pluginstance.section

        print("Default config options for %s\n" % sec)
        try:
            for opt, val in config.items(sec):
                print("%s:%s" % (opt, val))
        except NoSectionError:
            print("Plugin does not provide default options")
        sys.exit(0)

    # now switch to debug
    logging.getLogger().setLevel(logging.DEBUG)

    for pluginstance in mc.plugins + mc.appenders:
        if opts.config:
            for confpair in opts.config:
                section = pluginstance.section
                option, value = confpair.split(':', 1)
                if option.startswith('['):
                    ind = option.find(']')
                    section = option[1:ind]
                    option = option[ind + 1:]
                if not config.has_section(section):
                    config.add_section(section)
                config.set(section, option, value)

        if opts.lint:
            ret = pluginstance.lint()
            print("Lint success: %s" % ret)
            sys.exit(0)

    # prepare the suspect
    if opts.recipients == None or len(opts.recipients) == 0:
        opts.recipients = ["recipient@fuglu.local", ]

    if opts.eml:
        if opts.eml == '-':
            msgcontent = sys.stdin.read()
        else:
            msgcontent = open(opts.eml, 'rb').read()
        mailmessage = email.message_from_string(msgcontent)
    else:
        if opts.body:
            if opts.body == '-':
                body = sys.stdin.read()
            elif os.path.isfile(opts.body):
                body = open(opts.body, 'rb').read()
            else:
                body = opts.body
        else:
            body = "hello, world!"
        mailmessage = MIMEText(body)
        mailmessage.set_unixfrom(opts.sender)
        mailmessage['From'] = opts.sender
        mailmessage['To'] = opts.recipients[0]
        mailmessage['Subject'] = 'I beat the Sword Master'
        mailmessage[u'Date'] = formatdate()

    # headers
    if opts.headers:
        for hdrpair in opts.headers:
            name, val = hdrpair.split(':', 1)
            try:
                mailmessage.replace_header(name, val)
            except KeyError:
                mailmessage.add_header(name, val)

    # create tempfile...
    tmpfile = '/tmp/fuglu_dummy_message_in.eml'
    open(tmpfile, 'w').write(mailmessage.as_string())
    logging.info("Input file created as %s" % tmpfile)
    suspect = Suspect(opts.sender, opts.recipients[0], tmpfile)
    suspect.recipients = opts.recipients

    # tags
    if opts.tags:
        for tagpair in opts.tags:
            nme, valstr = tagpair.split(':', 1)
            if valstr == 'TRUE':
                val = True
            elif valstr == 'FALSE':
                val = False
            else:
                val = valstr
            suspect.set_tag(nme, val)

    scannerlist = mc.plugins
    for pluginstance in mc.prependers:
        logging.info("*** Running prepender: %s ***" % pluginstance)

        result = pluginstance.pluginlist(suspect, scannerlist)
        if result != None:
            origset = set(scannerlist)
            resultset = set(result)
            removed = list(origset - resultset)
            added = list(resultset - origset)
            if len(removed) > 0:
                logging.info(
                    'Prepender %s removed plugins: %s' % (pluginstance, list(map(str, removed))))
            if len(added) > 0:
                logging.info(
                    'Prepender %s added plugins: %s' % (pluginstance, list(map(str, added))))
            scannerlist = resultset
            logging.info("Scanner plugin list is now: %s" % scannerlist)

    for pluginstance in scannerlist:
        logging.info("*** Running plugin: %s ***" % pluginstance)
        ans = pluginstance.examine(suspect)
        message = ""
        if type(ans) is tuple:
            result, message = ans
        else:
            result = ans

        if result == None:
            result = DUNNO

        logging.info("Result: %s %s", actioncode_to_string(result), message)
        suspect.tags['decisions'].append((pluginstance.section, result))
        logging.info(suspect)

    for pluginstance in mc.appenders:
        logging.info("*** Running appender: %s ***" % pluginstance)
        pluginstance.process(suspect, DUNNO)
        message = ""
        logging.info(suspect)

    if suspect.is_modified():
        outfilename = '/tmp/fuglu_dummy_message_out.eml'
        out = open(outfilename, 'wb')
        out.write(suspect.get_source())
        out.close()
        logging.info(
            "Plugin modified the source -> modified message available as %s" % outfilename)

    if opts.console:
        run_debugconsole(
            suspect=suspect, plugin=pluginstance, result=result, config=config, prependers=mc.prependers, scanners=scannerlist, appenders=mc.appenders)
