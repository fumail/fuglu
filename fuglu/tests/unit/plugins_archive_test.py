from unittestsetup import TESTDATADIR

import unittest
import ConfigParser
import tempfile
import os

from fuglu.plugins.archive import ArchivePlugin


class ArchiveTestcase(unittest.TestCase):

    def setUp(self):

        self.tempfiles = []

        config = ConfigParser.RawConfigParser()
        config.add_section('main')
        config.set('main', 'disablebounces', '1')

        config.add_section('ArchivePlugin')
        config.set('ArchivePlugin', 'archivedir', '/tmp')
        config.set('ArchivePlugin', 'subdirtemplate', '')
        config.set('ArchivePlugin', 'filenametemplate', '${id}.eml')
        config.set('ArchivePlugin', 'storeoriginal', '1')
        config.set('ArchivePlugin', 'chmod', '700')
        config.set('ArchivePlugin', 'chown', '')
        config.set('ArchivePlugin', 'chgrp', '')

        tempfilename = tempfile.mktemp(
            suffix='archive', prefix='fuglu-unittest', dir='/tmp')
        fp = open(tempfilename, 'w')
        fp.write('From unittests.fuglu.org')
        self.tempfiles.append(tempfilename)
        config.set('ArchivePlugin', 'archiverules', tempfilename)

        self.config = config

    def tearDown(self):
        for tempfile in self.tempfiles:
            os.remove(tempfile)

    def test_original_message(self):
        """Test if the original message gets archived correctly"""
        from fuglu.shared import Suspect
        import shutil
        import tempfile

        tempfilename = tempfile.mktemp(
            suffix='archive', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy(TESTDATADIR + '/helloworld.eml', tempfilename)
        self.tempfiles.append(tempfilename)

        self.config.set('ArchivePlugin', 'storeoriginal', '1')
        candidate = ArchivePlugin(self.config)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tempfilename)
        origmessage = suspect.get_source()

        # modify the mesg
        msgrep = suspect.get_message_rep()
        msgrep['X-Changed-Something'] = 'Yes'
        suspect.setMessageRep(msgrep)

        filename = candidate.archive(suspect)
        self.assertTrue(filename != None and filename)

        self.tempfiles.append(filename)

        archivedmessage = open(filename, 'r').read()

        self.assertEqual(
            origmessage.strip(), archivedmessage.strip()), 'Archived message has been altered'

    def test_modified_message(self):
        """Test if the modified message gets archived correctly"""
        from fuglu.shared import Suspect
        import shutil
        import tempfile

        tempfilename = tempfile.mktemp(
            suffix='archive', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy(TESTDATADIR + '/helloworld.eml', tempfilename)
        self.tempfiles.append(tempfilename)

        self.config.set('ArchivePlugin', 'storeoriginal', '0')
        candidate = ArchivePlugin(self.config)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tempfilename)
        origmessage = suspect.get_source()
        # modify the mesg
        msgrep = suspect.get_message_rep()
        msgrep['X-Changed-Something'] = 'Yes'
        suspect.setMessageRep(msgrep)

        filename = candidate.archive(suspect)
        self.assertTrue(filename != None and filename)

        self.tempfiles.append(filename)

        archivedmessage = open(filename, 'r').read()
        self.assertNotEqual(origmessage.strip(), archivedmessage.strip(
        )), 'Archived message should have stored modified message'
