# -*- coding: UTF-8 -*-
import unittest
import sys
import email
from os.path import join
from fuglu.extensions.mailattach import MailAttachMgr
from unittestsetup import TESTDATADIR, CONFDIR

class FileArchiveBase(unittest.TestCase):
    def testMailAttachment(self):

        #tempfile = join(TESTDATADIR,"6mbrarattachment.eml")
        tempfile = join(TESTDATADIR,"nestedarchive.eml")

        if sys.version_info > (3,):
            # Python 3 and larger
            # file should be binary...

            # IMPORTANT: It is possible to use email.message_from_bytes BUT this will automatically replace
            #            '\r\n' in the message (_payload) by '\n' and the endtoend_test.py will fail!
            with open(tempfile, 'rb') as fh:
                source = fh.read()
            msgrep = email.message_from_bytes(source)
        else:
            # Python 2.x
            with open(tempfile, 'r') as fh:
                msgrep = email.message_from_file(fh)
        mAttachMgr = MailAttachMgr(msgrep)
        #self.assertEqual([])Filenames, base   Level : [nestedarchive.tar.gz, unnamed.txt]
        fnames_base_level   = sorted(["nestedarchive.tar.gz", "unnamed.txt"])
        fnames_first_level  = sorted(["level1.tar.gz", "level0.txt", "unnamed.txt"])
        fnames_second_level = sorted(["level2.tar.gz", "level1.txt", "level0.txt", "unnamed.txt"])
        fnames_all_levels   = sorted(["level6.txt", "level5.txt", "level4.txt", "level3.txt", "level2.txt", "level1.txt", "level0.txt", "unnamed.txt"])


        print("Filenames, Level  [0:0] : [%s]"%", ".join(mAttachMgr.get_fileslist()))
        print("Filenames, Levels [0:1] : [%s]"%", ".join(mAttachMgr.get_fileslist(1)))
        print("Filenames, Levels [0:2] : [%s]"%", ".join(mAttachMgr.get_fileslist(2)))
        print("Filenames, Levels [0: ] : [%s]"%", ".join(mAttachMgr.get_fileslist(None)))

        self.assertEqual(fnames_base_level,  sorted(mAttachMgr.get_fileslist()))
        self.assertEqual(fnames_first_level, sorted(mAttachMgr.get_fileslist(1)))
        self.assertEqual(fnames_second_level,sorted(mAttachMgr.get_fileslist(2)))
        self.assertEqual(fnames_all_levels,  sorted(mAttachMgr.get_fileslist(None)))

        print("\n")
        print("-------------------------------------")
        print("- Extract objects util second level -")
        print("-------------------------------------")
        # list has to be sorted according to filename in order to be able to match
        # target list in Python2 and 3
        secAttList = sorted(mAttachMgr.get_objectlist(2),key=lambda obj: obj.filename)
        self.assertEqual(len(fnames_second_level),len(secAttList))
        for att,afname in zip(secAttList,fnames_second_level):
            print(att)
            self.assertEqual(afname,att.filename)

        print("\n")
        print("--------------------------------------------")
        print("- Extract objects until there's no archive -")
        print("--------------------------------------------")
        # list has to be sorted according to filename in order to be able to match
        # target list in Python2 and 3
        fullAttList = sorted(mAttachMgr.get_objectlist(None),key=lambda obj: obj.filename)
        for att,afname in zip(fullAttList,fnames_all_levels):
            print(att)
            self.assertEqual(afname,att.filename)

