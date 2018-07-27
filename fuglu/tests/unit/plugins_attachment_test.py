from unittestsetup import TESTDATADIR, CONFDIR

import unittest
import os
import tempfile
import shutil
from nose.tools import nottest

try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

import fuglu
from fuglu.plugins.attachment import FiletypePlugin, RulesCache
from fuglu.shared import actioncode_to_string, Suspect, DELETE, DUNNO

# we import it here to make sure the test system has the library installed
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
        config.set('FiletypePlugin', 'archivecontentmaxsize', 500000)
        config.set('FiletypePlugin', 'archiveextractlevel', -1)
        config.set('FiletypePlugin', 'enabledarchivetypes', '')
        self.candidate = FiletypePlugin(config)

    def test_dbrules(self):
        """Test if db rules correctly override defaults"""

        testdata = u"""
        INSERT INTO attachmentrules(scope,checktype,action,regex,description,prio) VALUES
        ('recipient@unittests.fuglu.org','contenttype','allow','application/x-executable','this user likes exe',1)
        """
        self.session.execute(testdata)
        # copy file rules
        tmpfile = tempfile.NamedTemporaryFile(
            suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy(TESTDATADIR + '/binaryattachment.eml', tmpfile.name)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tmpfile.name)

        result = self.candidate.examine(suspect)
        resstr = actioncode_to_string(result)
        self.assertEqual(resstr, "DUNNO")

        # another recipient should still get the block
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient2@unittests.fuglu.org', tmpfile.name)

        result = self.candidate.examine(suspect)
        if type(result) is tuple:
            result, message = result
        resstr = actioncode_to_string(result)
        self.assertEqual(resstr, "DELETE")
        tmpfile.close()


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
        config.set('FiletypePlugin', 'archivecontentmaxsize', '7000000')
        config.set('FiletypePlugin', 'archiveextractlevel', -1)
        config.set('FiletypePlugin', 'enabledarchivetypes', '')

        config.add_section('main')
        config.set('main', 'disablebounces', '1')
        self.candidate = FiletypePlugin(config)
        self.rulescache = RulesCache(self.tempdir)
        self.candidate.rulescache = self.rulescache

    def tearDown(self):
        os.remove('%s/default-filenames.conf' % self.tempdir)
        os.remove('%s/default-filetypes.conf' % self.tempdir)
        os.remove(self.template)
        shutil.rmtree(self.tempdir)

    def test_hiddenbinary(self):
        """Test if hidden binaries get detected correctly"""
        # copy file rules
        tmpfile = tempfile.NamedTemporaryFile(
            suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy(TESTDATADIR + '/binaryattachment.eml', tmpfile.name)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tmpfile.name)

        result = self.candidate.examine(suspect)
        if type(result) is tuple:
            result, message = result
        tmpfile.close()
        self.assertEqual(result, DELETE)

    def test_umlaut_in_zip(self):
        """Issue 69: Test if zip with files that contain umlauts are extracted ok"""
        tmpfile = tempfile.NamedTemporaryFile(
            suffix='badattach', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy(TESTDATADIR + '/umlaut-in-attachment.eml', tmpfile.name)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tmpfile.name)

        result = self.candidate.examine(suspect)
        if type(result) is tuple:
            result, message = result
        tmpfile.close()
        self.assertEqual(result, DUNNO)


    def test_archiveextractsize(self):
        """Test archive extract max filesize"""
        # copy file rules
        for testfile in ['6mbzipattachment.eml', '6mbrarattachment.eml']:
            try:
                tmpfile = tempfile.NamedTemporaryFile(
                    suffix='virus', prefix='fuglu-unittest', dir='/tmp')
                shutil.copy("%s/%s" % (TESTDATADIR, testfile), tmpfile.name)

                user = 'recipient-sizetest@unittests.fuglu.org'
                conffile = self.tempdir + "/%s-archivefiletypes.conf" % user
                # the largefile in the test message is just a bunch of zeroes
                open(conffile, 'w').write(
                    "deny application\/octet\-stream no data allowed")
                self.rulescache._loadrules()
                suspect = Suspect(
                    'sender@unittests.fuglu.org', user, tmpfile.name)

                # backup old limits from config file
                oldlimit         = self.candidate.config.getint( 'FiletypePlugin', 'archivecontentmaxsize')
                oldlimit_aelevel = self.candidate.config.getint( 'FiletypePlugin', 'archiveextractlevel')

                # now set the limit to 4 mb, the file should be skipped now
                #
                # check log
                # reason of skipping should be the size is to large, file largefile/6mbfile is not extracted
                self.candidate.config.set(
                    'FiletypePlugin', 'archivecontentmaxsize', 4000000)
                result = self.candidate.examine(suspect)
                if type(result) is tuple:
                    result, message = result
                self.assertEqual(result, DUNNO, 'large file should be skipped (not extracted)')

                self.candidate.config.set(
                    'FiletypePlugin', 'archivecontentmaxsize', 7000000)
                result = self.candidate.examine(suspect)
                if type(result) is tuple:
                    result, message = result
                self.assertEqual(
                    result, DELETE, 'extracted large file should be blocked')

                # now set the limit to 5 mb, the file should be skipped now
                # check log
                # reason of skipping should be the size is to large for check, file largefile/6mbfile is already extracted
                self.candidate.config.set(
                    'FiletypePlugin', 'archivecontentmaxsize', 5000000)
                result = self.candidate.examine(suspect)
                if type(result) is tuple:
                    result, message = result
                self.assertEqual(result, DUNNO, 'large file should be skipped')

                # now set the limit to 7 mb, the file should be skipped now
                self.candidate.config.set( 'FiletypePlugin', 'archivecontentmaxsize', 7000000)
                self.candidate.config.set( 'FiletypePlugin', 'archiveextractlevel', 0)

                result = self.candidate.examine(suspect)
                if type(result) is tuple:
                    result, message = result
                self.assertEqual(result, DUNNO, 'large file should be skipped')

                # reset config
                self.candidate.config.set( 'FiletypePlugin', 'archivecontentmaxsize', oldlimit)
                self.candidate.config.set( 'FiletypePlugin', 'archiveextractlevel', oldlimit_aelevel)
            finally:
                tmpfile.close()
                os.remove(conffile)

    def test_archivename(self):
        """Test check archive names"""

        for testfile in ['6mbzipattachment.eml', '6mbrarattachment.eml']:
            try:
                # copy file rules
                tmpfile = tempfile.NamedTemporaryFile(
                    suffix='virus', prefix='fuglu-unittest', dir='/tmp')
                shutil.copy("%s/%s" % (TESTDATADIR, testfile), tmpfile.name)

                user = 'recipient-archivenametest@unittests.fuglu.org'
                conffile = self.tempdir + "/%s-archivenames.conf" % user
                open(conffile, 'w').write(
                    "deny largefile user does not like the largefile within a zip\ndeny 6mbfile user does not like the largefile within a zip")
                self.rulescache._loadrules()
                suspect = Suspect( 'sender@unittests.fuglu.org', user, tmpfile.name)

                result = self.candidate.examine(suspect)
                if type(result) is tuple:
                    result, message = result
                self.assertEqual(
                    result, DELETE, 'archive containing blocked filename was not blocked')
            finally:
                tmpfile.close()
                os.remove(conffile)

    def test_archivename_nestedarchive(self):
        """Test check archive names in nested archive"""

        #---
        # Note:
        #---
        # mail testedarchive.eml contains the attachment "nestedarchive.tar.gz"
        # which has the following nested structure:
        #---
        # Level : (extracted from archive  ) -> Files
        #---
        # 0     : nestedarchive.tar.gz
        # 1     : (extracting level1.tar.gz) -> level0.txt   level1.tar.gz
        # 2     : (extracting level1.tar.gz) -> level1.txt   level2.tar.gz
        # 3     : (extracting level2.tar.gz) -> level2.txt   level3.tar.gz
        # 4     : (extracting level3.tar.gz) -> level3.txt   level4.tar.gz
        # 5     : (extracting level4.tar.gz) -> level4.txt   level5.tar.gz
        # 6     : (extracting level5.tar.gz) -> level5.txt   level6.tar.gz
        # 7     : (extracting level6.tar.gz) -> level6.txt

        testfile = os.path.join(TESTDATADIR,"nestedarchive.eml")
        try:
            # copy file rules
            user = 'recipient-archivenametest@unittests.fuglu.org'
            conffile = self.tempdir + "/%s-archivenames.conf" % user
            open(conffile, 'w').write(
                "deny level6.txt user does not like the files in nested archives \ndeny 6mbfile user does not like the largefile within a zip")
            self.rulescache._loadrules()

            suspect = Suspect('sender@unittests.fuglu.org', user, testfile)

            oldlimit_aelevel = self.candidate.config.getint( 'FiletypePlugin', 'archiveextractlevel')

            #----
            self.candidate.config.set( 'FiletypePlugin', 'archiveextractlevel', 6)

            result = self.candidate.examine(suspect)
            if type(result) is tuple:
                result, message = result
            self.assertEqual( result, DUNNO, 'archive containing blocked filename should not be extracted')

            #----
            self.candidate.config.set( 'FiletypePlugin', 'archiveextractlevel', 7)

            result = self.candidate.examine(suspect)
            if type(result) is tuple:
                result, message = result
            self.assertEqual( result, DELETE, 'archive containing blocked filename was not blocked')

            self.candidate.config.set( 'FiletypePlugin', 'archiveextractlevel', oldlimit_aelevel)
        finally:
            os.remove(conffile)

    def test_hiddenpart(self):
        """Test for hidden part in message epilogue"""
        testfile='hiddenpart.eml'
        try:
            tmpfile = tempfile.NamedTemporaryFile(
                suffix='hidden', prefix='fuglu-unittest', dir='/tmp')
            shutil.copy("%s/%s" % (TESTDATADIR, testfile), tmpfile.name)

            user = 'recipient-hiddenpart@unittests.fuglu.org'
            conffile = self.tempdir + "/%s-filetypes.conf" % user
            # the largefile in the test message is just a bunch of zeroes
            open(conffile, 'w').write(
                "deny application\/zip no zips allowed")
            self.rulescache._loadrules()
            suspect = Suspect(
                'sender@unittests.fuglu.org', user, tmpfile.name)

            result = self.candidate.examine(suspect)
            if type(result) is tuple:
                result, message = result
            self.assertEqual(
                result, DELETE, 'hidden message part was not detected')

        finally:
            tmpfile.close()
            os.remove(conffile)


    def test_archive_wrong_extension(self):
        """Test if archives don't fool us with forged file extensions"""
        testfile = 'wrongextension.eml'
        try:
            tmpfile = tempfile.NamedTemporaryFile(
                suffix='wrongext', prefix='fuglu-unittest', dir='/tmp')
            shutil.copy("%s/%s" % (TESTDATADIR, testfile), tmpfile.name)

            user = 'recipient-wrongarchextension@unittests.fuglu.org'
            conffile = self.tempdir + "/%s-archivenames.conf" % user
            # the largefile in the test message is just a bunch of zeroes
            open(conffile, 'w').write(
                "deny \.exe$ exe detected in zip with wrong extension")
            self.rulescache._loadrules()
            suspect = Suspect(
                'sender@unittests.fuglu.org', user, tmpfile.name)

            result = self.candidate.examine(suspect)
            if type(result) is tuple:
                result, message = result
            self.assertEqual(
                result, DELETE, 'exe in zip with .gz extension was not detected')

        finally:
            tmpfile.close()
            os.remove(conffile)
