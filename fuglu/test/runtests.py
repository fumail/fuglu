#!/usr/bin/python

import unittest
import sys
import logging
import ConfigParser
import os

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

def getModules():
    """returns all plugin modules"""
    global globalconfig
    mods=[]
    plugins=globalconfig.get('main', 'plugins').split(',')
    for structured_name in plugins:
        if structured_name=="":
            continue
        component_names = structured_name.split('.')
        mod='.'.join(component_names[:-1])
        mods.append(mod)
    plugins=globalconfig.get('main', 'prependers').split(',')
    for structured_name in plugins:
        if structured_name=="":
            continue
        component_names = structured_name.split('.')
        mod='.'.join(component_names[:-1])
        mods.append(mod)
    plugins=globalconfig.get('main', 'appenders').split(',')
    for structured_name in plugins:
        if structured_name=="":
            continue
        component_names = structured_name.split('.')
        mod='.'.join(component_names[:-1])
        mods.append(mod)
    return mods


testonly=None
if len(sys.argv)>1:
    testonly=sys.argv[1:]


loader=unittest.TestLoader()
alltests=unittest.TestSuite()
plugdir=globalconfig.get('main', 'plugindir').strip()
if plugdir!="":
    sys.path.append(plugdir)
modules=getModules()
modules.insert(0,'fuglu.stats')
modules.insert(0,'fuglu.scansession')
modules.insert(0,'fuglu.connectors.smtpconnector')
modules.insert(0,'fuglu.connectors.milterconnector')
modules.insert(0,'fuglu.connectors.ncblackholeconnector')
modules.insert(0,'fuglu.bounce')
modules.insert(0,'fuglu.shared')
modules.insert(0,'fuglu.core')

for mod in modules:
    if testonly!=None and mod not in testonly:
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
runner.run(alltests)

print ""
print "Debug Output written to:%s"%logfile