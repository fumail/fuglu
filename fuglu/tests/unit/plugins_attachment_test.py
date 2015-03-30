from unittestsetup import TESTDATADIR, CONFDIR

import unittest
import os
from ConfigParser import RawConfigParser
import tempfile
import shutil
from nose.tools import nottest

import fuglu
from fuglu.plugins.attachment import FiletypePlugin
from fuglu.shared import actioncode_to_string, Suspect, DELETE, DUNNO

#we import it here to make sure the test system has the library installed
import rarfile


class DatabaseConfigTestCase(unittest.TestCase):

    """Testcases for the Attachment Checker Plugin"""

    def setUp(self):
        testfile = "/tmp/attachconfig.db"
        if os.path.exists(testfile):
            os.remove(testfile)
        # important: 4 slashes for absolute paths!
        testdb = "sqlite:///%s" % testfile

        sql = """create table attachmentrules(
        id integer not null primary key,
        scope varchar(255) not null,
        checktype varchar(20) not null,
        action varchar(255) not null,
        regex varchar(255) not null,
        description varchar(255) not null,
        prio integer not null
        )
        """

        self.session = fuglu.extensions.sql.get_session(testdb)
        self.session.flush()
        self.session.execute(sql)
        self.tempdir = tempfile.mkdtemp('attachtestdb', 'fuglu')
        self.template = '%s/blockedfile.tmpl' % self.tempdir
        shutil.copy(
            CONFDIR + '/templates/blockedfile.tmpl.dist', self.template)
        shutil.copy(CONFDIR + '/rules/default-filenames.conf.dist',
                    '%s/default-filenames.conf' % self.tempdir)
        shutil.copy(CONFDIR + '/rules/default-filetypes.conf.dist',
                    '%s/default-filetypes.conf' % self.tempdir)
        config = RawConfigParser()
        config.add_section('FiletypePlugin')
        config.set('FiletypePlugin', 'template_blockedfile', self.template)
        config.set('FiletypePlugin', 'rulesdir', self.tempdir)
        config.set('FiletypePlugin', 'dbconnectstring', testdb)
        config.set('FiletypePlugin', 'blockaction', 'DELETE')
        config.set('FiletypePlugin', 'sendbounce', 'True')
        config.set('FiletypePlugin', 'query',
                   'SELECT action,regex,description FROM attachmentrules WHERE scope=:scope AND checktype=:checktype ORDER BY prio')
        config.add_section('main')
        config.set('main', 'disablebounces', '1')
        config.set('FiletypePlugin', 'checkarchivenames', 'False')
        config.set('FiletypePlugin', 'checkarchivecontent', 'False')
        config.set('FiletypePlugin', 'archivecontentmaxsize', '500000')
        self.candidate = FiletypePlugin(config)

    def test_dbrules(self):
        """Test if db rules correctly override defaults"""

        testdata = u"""
        INSERT INTO attachmentrules(scope,checktype,action,regex,description,prio) VALUES
        ('recipient@unittests.fuglu.org','contenttype','allow','application/x-executable','this user likes exe',1)
        """
        self.session.execute(testdata)
        # copy file rules
        tempfilename = tempfile.mktemp(
            suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy(TESTDATADIR + '/binaryattachment.eml', tempfilename)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tempfilename)

        result = self.candidate.examine(suspect)
        resstr = actioncode_to_string(result)
        self.assertEquals(resstr, "DUNNO")

        # another recipient should still get the block
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient2@unittests.fuglu.org', tempfilename)

        result = self.candidate.examine(suspect)
        if type(result) is tuple:
            result, message = result
        resstr = actioncode_to_string(result)
        self.assertEquals(resstr, "DELETE")
        os.remove(tempfilename)


class AttachmentPluginTestCase(unittest.TestCase):

    """Testcases for the Attachment Checker Plugin"""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp('attachtest', 'fuglu')
        self.template = '%s/blockedfile.tmpl' % self.tempdir
        shutil.copy(
            CONFDIR + '/templates/blockedfile.tmpl.dist', self.template)
        shutil.copy(CONFDIR + '/rules/default-filenames.conf.dist',
                    '%s/default-filenames.conf' % self.tempdir)
        shutil.copy(CONFDIR + '/rules/default-filetypes.conf.dist',
                    '%s/default-filetypes.conf' % self.tempdir)
        config = RawConfigParser()
        config.add_section('FiletypePlugin')
        config.set('FiletypePlugin', 'template_blockedfile', self.template)
        config.set('FiletypePlugin', 'rulesdir', self.tempdir)
        config.set('FiletypePlugin', 'blockaction', 'DELETE')
        config.set('FiletypePlugin', 'sendbounce', 'True')
        config.set('FiletypePlugin', 'checkarchivenames', 'True')
        config.set('FiletypePlugin', 'checkarchivecontent', 'True')
        config.set('FiletypePlugin', 'archivecontentmaxsize', '5000000')

        config.add_section('main')
        config.set('main', 'disablebounces', '1')
        self.candidate = FiletypePlugin(config)

    def tearDown(self):
        os.remove('%s/default-filenames.conf' % self.tempdir)
        os.remove('%s/default-filetypes.conf' % self.tempdir)
        os.remove(self.template)
        os.rmdir(self.tempdir)

    def test_hiddenbinary(self):
        """Test if hidden binaries get detected correctly"""
        # copy file rules
        tempfilename = tempfile.mktemp(
            suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy(TESTDATADIR + '/binaryattachment.eml', tempfilename)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tempfilename)

        result = self.candidate.examine(suspect)
        if type(result) is tuple:
            result, message = result
        os.remove(tempfilename)
        self.failIf(result != DELETE)

    @nottest
    def test_utf8msg(self):
        """Test utf8 msgs are parsed ok - can cause bugs on some magic implementations (eg. centos)
        disabled - need new sample"""

        tempfilename = tempfile.mktemp(
            suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy(TESTDATADIR + '/utf8message.eml', tempfilename)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tempfilename)

        result = self.candidate.examine(suspect)
        if type(result) is tuple:
            result, message = result
        os.remove(tempfilename)
        self.assertEquals(result, DUNNO)

    def test_archiveextractsize(self):
        """Test archive extract max filesize"""
        # copy file rules
        for testfile in ['6mbzipattachment.eml', '6mbrarattachment.eml']:
            try:
                tempfilename = tempfile.mktemp(
                    suffix='virus', prefix='fuglu-unittest', dir='/tmp')
                shutil.copy("%s/%s"%(TESTDATADIR,testfile), tempfilename)

                user = 'recipient-sizetest@unittests.fuglu.org'
                conffile = self.tempdir + "/%s-archivefiletypes.conf" % user
                # the largefile in the test message is just a bunch of zeroes
                open(conffile, 'w').write(
                    "deny application\/octet\-stream no data allowed")

                suspect = Suspect(
                    'sender@unittests.fuglu.org', user, tempfilename)

                # test with high limit first
                oldlimit = self.candidate.config.get(
                    'FiletypePlugin', 'archivecontentmaxsize')
                self.candidate.config.set(
                    'FiletypePlugin', 'archivecontentmaxsize', '7000000')
                result = self.candidate.examine(suspect)
                if type(result) is tuple:
                    result, message = result
                self.failIf(result != DELETE, 'extracted large file should be blocked')

                # now set the limit to 5 mb, the file should be skipped now
                self.candidate.config.set(
                    'FiletypePlugin', 'archivecontentmaxsize', '5000000')
                result = self.candidate.examine(suspect)
                if type(result) is tuple:
                    result, message = result
                self.failIf(result != DUNNO, 'large file should be skipped')

                # reset config
                self.candidate.config.set(
                    'FiletypePlugin', 'archivecontentmaxsize', oldlimit)
            finally:
                os.remove(tempfilename)
                os.remove(conffile)

    def test_archivename(self):
        """Test check archive names"""

        for testfile in ['6mbzipattachment.eml', '6mbrarattachment.eml']:
            try:
            # copy file rules
                tempfilename = tempfile.mktemp(
                    suffix='virus', prefix='fuglu-unittest', dir='/tmp')
                shutil.copy("%s/%s"%(TESTDATADIR,testfile), tempfilename)

                user = 'recipient-archivenametest@unittests.fuglu.org'
                conffile = self.tempdir + "/%s-archivenames.conf" % user
                open(conffile, 'w').write(
                    "deny largefile user does not like the largefile within a zip\ndeny 6mbfile user does not like the largefile within a zip")

                suspect = Suspect(
                    'sender@unittests.fuglu.org', user, tempfilename)

                result = self.candidate.examine(suspect)
                if type(result) is tuple:
                    result, message = result
                self.failIf(
                    result != DELETE, 'archive containing blocked filename was not blocked')
            finally:
                os.remove(tempfilename)
                os.remove(conffile)
