#!/usr/bin/python
# deploy:
#./make_sphinx_plugin_doc.py > /home/gryphius/gitspace/fuglu.gh-pages/source/includedplugins-autogen.txt
# cd /home/gryphius/gitspace/fuglu.gh-pages/
# make html
# firefox index.html
# check for errors, update docstring in plugin if necessary!
# git commit -a -m 'updated doc'
# git push

import inspect
import sys
import os

this_file = inspect.currentframe().f_code.co_filename
workdir = os.path.dirname(os.path.abspath(this_file))
os.chdir(workdir)
sys.path.insert(0, '../../src')

import fuglu
from fuglu.plugins import *
try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser


if __name__ == '__main__':
    config = RawConfigParser()

    pluginlist = [
        sa.SAPlugin(config),
        clamav.ClamavPlugin(config),
        attachment.FiletypePlugin(config),
        archive.ArchivePlugin(config),
        vacation.VacationPlugin(config),
        sssp.SSSPPlugin(config),
        fprot.FprotPlugin(config),
        icap.ICAPPlugin(config),
        drweb.DrWebPlugin(config),
        actionoverride.ActionOverridePlugin(config),
        script.ScriptFilter(config),
        domainauth.DKIMSignPlugin(config),
        domainauth.DKIMVerifyPlugin(config),
        domainauth.SPFPlugin(config),

        # prependers
        p_skipper.PluginSkipper(config),
        p_fraction.PluginFraction(config),
        p_debug.MessageDebugger(config),

        # appenders
        a_statsd.PluginTime(config),
        a_statsd.MessageStatus(config),
        a_statsd.MessageStatusPerRecipient(config),
    ]

    headerchar = '.'

    subheaderchar = '-'

    for plugin in pluginlist:
        plug_docstring = plugin.__doc__
        if plug_docstring == None:
            plug_docstring = ''
        plug_class = plugin.__class__.__name__
        plug_module = plugin.__module__
        plug_fqdn = "%s.%s" % (plug_module, plug_class)
        plug_humanreadable = str(plugin)

        sphinxdoc = ""

        # write the header
        sphinxdoc += "%s\n" % plug_humanreadable
        sphinxdoc += "".join([headerchar for x in plug_humanreadable]) + "\n"
        sphinxdoc += "\n"

        # info
        sphinxdoc += "Plugin: %s\n" % plug_fqdn
        sphinxdoc += "\n"

        # write the docstring
        sphinxdoc += plug_docstring + "\n\n"

        # config
        configsubtitle = "Configuration"
        sphinxdoc += "%s\n" % configsubtitle
        sphinxdoc += "".join([subheaderchar for x in configsubtitle]
                             ) + "\n\n::\n\n"
        tab = "    "
        sphinxdoc += tab + "[%s]\n" % plug_class
        for optionname, infodic in plugin.requiredvars.items():
            defaultval = ''

            if 'default' in infodic:
                defaultval = infodic['default']

            if 'description' in infodic:
                description = infodic['description']
                description = description.replace('\n', '\n' + tab + '#')
                sphinxdoc += tab + "#%s\n" % description
            sphinxdoc += tab + optionname + "=" + defaultval + "\n\n"

        print("")
        print(sphinxdoc)
