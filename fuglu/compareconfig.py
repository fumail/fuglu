#!/usr/bin/python
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
import sys
import os

sys.path.insert(0, 'src')
try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

from fuglu.funkyconsole import FunkyConsole

fc = FunkyConsole()

fugluconfigfile = '/etc/fuglu/fuglu.conf'
dconfdir = '/etc/fuglu/conf.d'


currentconfig = ConfigParser()
currentconfig.readfp(open(fugluconfigfile))

# load conf.d
if os.path.isdir(dconfdir):
    filelist = os.listdir(dconfdir)
    configfiles = [dconfdir + '/' + c for c in filelist if c.endswith('.conf')]
    readfiles = currentconfig.read(configfiles)
    print('Read additional files: %s' % (readfiles))

newconfig = ConfigParser()
newconfig.read('conf/fuglu.conf.dist')

newsections = newconfig.sections()

# values that usually differ from the default
excludelist = [
    ('main', 'plugins'),
    ('main', 'prependers'),
    ('main', 'identifier'),
    ('main', 'appenders'),
    ('main', 'trashdir'),
    ('ArchivePlugin', 'archivedir'),
]

for newsection in newsections:
    # print "Checking section %s"%newsection
    if not currentconfig.has_section(newsection):
        print("%s: section '%s' is missing in your current config" % (
            fc.strcolor('MISSING SECTION', 'red'), fc.strcolor(newsection, 'cyan')))
        continue

    newitems = newconfig.options(newsection)
    currentitems = currentconfig.options(newsection)

    toomanyitems = set(currentitems) - set(newitems)
    if len(toomanyitems) > 0:
        for item in toomanyitems:
            print("%s: Your option '%s' in section '%s' is not known in new config" % (fc.strcolor(
                'UNKNOWN OPTION', 'yellow'), fc.strcolor(item, 'cyan'), fc.strcolor(newsection, 'cyan')))

    for key in newitems:
        defaultvalue = newconfig.get(newsection, key)
        if not currentconfig.has_option(newsection, key):
            print("%s: add option '%s' in section '%s'. Default value is: '%s'" % (fc.strcolor('MISSING OPTION',
                                                                                               'red'), fc.strcolor(key, 'cyan'), fc.strcolor(newsection, 'cyan'), fc.strcolor(defaultvalue, 'cyan')))
            continue

        currentvalue = currentconfig.get(newsection, key)
        if currentvalue != defaultvalue and (newsection, key) not in excludelist:
            print("%s: option '%s' in section '%s'. your value '%s' differs from default '%s'" % (fc.strcolor('VALUE', 'yellow'), fc.strcolor(
                key, 'cyan'), fc.strcolor(newsection, 'cyan'), fc.strcolor(currentvalue, 'cyan'), fc.strcolor(defaultvalue, 'cyan')))
