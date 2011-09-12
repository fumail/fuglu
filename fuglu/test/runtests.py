#!/usr/bin/python

import unittest
import sys
import logging
import ConfigParser
import os


#make sure working dir is set to the directory where runtests.py resides
import inspect
this_file = inspect.currentframe().f_code.co_filename
workdir=os.path.dirname(os.path.abspath(this_file))
os.chdir(workdir)

sys.path.insert(0,'../src')

homedir=os.getenv("HOME")
devdir='%s/fuglu-dev'%homedir
if os.path.exists(devdir):
    print "Including plugins in %s"%devdir
    sys.path.insert(0,devdir)

#overwrite logger
console = logging.StreamHandler()
console.setLevel(logging.INFO)
consoleformatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(consoleformatter)


logfile='/tmp/fuglu-test.log'

filelogger=logging.FileHandler(logfile, 'w')
filelogger.setLevel(logging.DEBUG)
fileformatter=logging.Formatter("%(asctime)s %(name)-12s: %(levelname)s %(message)s")
filelogger.setFormatter(fileformatter)

rootlogger=logging.getLogger('')
rootlogger.setLevel(logging.DEBUG)
rootlogger.addHandler(console)
rootlogger.addHandler(filelogger)


#load config
globalconfig=ConfigParser.ConfigParser()
readconfig=globalconfig.read(['../conf/fuglu.conf.dist','%s/test.conf'%devdir])
print readconfig

def getPluginModules():
    from fuglu.plugins import __all__ as allplugs
    return map(lambda x:"fuglu.plugins.%s"%x, allplugs)

def getExtensionModules():
    from fuglu.extensions import __all__ as allplugs
    return map(lambda x:"fuglu.extensions.%s"%x, allplugs)

def getConnectorModules():
    from fuglu.connectors import __all__ as allplugs
    return map(lambda x:"fuglu.connectors.%s"%x, allplugs)

def getCoreModules():
    from fuglu import __all__ as allplugs
    return map(lambda x:"fuglu.%s"%x, allplugs)
    

testonly=None
if len(sys.argv)>1:
    testonly=sys.argv[1:]


loader=unittest.TestLoader()
alltests=unittest.TestSuite()
plugdir=globalconfig.get('main', 'plugindir').strip()
if plugdir!="":
    sys.path.append(plugdir)
modules=[]
modules.extend(getCoreModules())
modules.extend(getExtensionModules())
modules.extend(getConnectorModules())
modules.extend(getPluginModules())

if globalconfig.has_section('test'):
    if globalconfig.has_option('test', 'includemodules'):
        addmods=globalconfig.get('test', 'includemodules').split(',')
        print "Additional modules specified in test config: %s"%addmods
        modules.extend(addmods)

for mod in modules:
    if testonly!=None and mod not in testonly:
        continue
    if mod==None or mod=='':
        continue
    ldmod=__import__(mod)
    suite=loader.loadTestsFromName(mod)
    count=suite.countTestCases()
    print "found %s tests in %s"%(count,mod)
    alltests.addTests(suite)
print "---------------------------"
print "Total %s tests in Testsuite"%alltests.countTestCases()
print ""
print "STARTING TESTS"
print ""

runner=unittest.TextTestRunner()
result=runner.run(alltests)

print ""
print "Debug Output written to:%s"%logfile

if result.wasSuccessful():
    print "ALL TESTS SUCCESSFUL"
    sys.exit(0)
else:
    print "TESTRUN FAILED"
    sys.exit(1)