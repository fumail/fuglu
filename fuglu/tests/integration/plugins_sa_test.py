import integrationtestsetup
import unittest
from fuglu.plugins.sa import SAPlugin
import os
from fuglu.shared import ScannerPlugin, DELETE, DUNNO, DEFER, REJECT, Suspect, string_to_actioncode, apply_template


class SAPluginTestCase(unittest.TestCase):

    """Testcases for the Stub Plugin"""

    def setUp(self):
        try:
            from configparser import RawConfigParser
        except ImportError:
            from ConfigParser import RawConfigParser
        config = RawConfigParser()
        config.add_section('main')
        config.set('main', 'prependaddedheaders', 'X-Fuglu-')

        config.add_section('SAPlugin')
        config.set('SAPlugin', 'host', '127.0.0.1')
        config.set('SAPlugin', 'port', '783')
        config.set('SAPlugin', 'timeout', '5')
        config.set('SAPlugin', 'retries', '3')
        config.set('SAPlugin', 'peruserconfig', '0')
        config.set('SAPlugin', 'maxsize', '500000')
        config.set('SAPlugin', 'spamheader', 'X-Spam-Status')
        config.set('SAPlugin', 'lowspamaction', 'DUNNO')
        config.set('SAPlugin', 'highspamaction', 'REJECT')
        config.set('SAPlugin', 'problemaction', 'DEFER')
        config.set('SAPlugin', 'highspamlevel', '15')
        config.set('SAPlugin', 'forwardoriginal', 'False')
        config.set('SAPlugin', 'scanoriginal', 'False')
        config.set('SAPlugin', 'rejectmessage', '')

        # sql blacklist
        testfile = "/tmp/sa_test.db"
        if os.path.exists(testfile):
            os.remove(testfile)
        # important: 4 slashes for absolute paths!
        self.testdb = "sqlite:///%s" % testfile

        sql = """SELECT value FROM userpref WHERE preference='blacklist_from' AND username in ('@GLOBAL','%' || ${to_domain},${to_address})"""

        config.set('SAPlugin', 'sql_blacklist_dbconnectstring', self.testdb)
        config.set('SAPlugin', 'sql_blacklist_sql', sql)
        config.set('SAPlugin', 'check_sql_blacklist', 'False')

        self.candidate = SAPlugin(config)

    def test_score(self):
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', '/dev/null')
        stream = """Date: Mon, 08 Sep 2008 17:33:54 +0200
To: oli@unittests.fuglu.org
From: oli@unittests.fuglu.org
Subject: test scanner

  XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
"""
        suspect.set_source(stream)
        result = self.candidate.examine(suspect)
        if type(result) is tuple:
            result, message = result
        score = int(suspect.get_tag('SAPlugin.spamscore'))
        self.assertTrue(
            score > 999, "GTUBE mails should score ~1000 , we got %s" % score)
        self.assertTrue(result == REJECT, 'High spam should be rejected')

    def test_symbols(self):
        stream = """Date: Mon, 08 Sep 2008 17:33:54 +0200
To: oli@unittests.fuglu.org
From: oli@unittests.fuglu.org
Subject: test scanner

  XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
"""
        spamstatus, spamscore, rules = self.candidate.safilter_symbols(
            stream, 'oli@unittests.fuglu.org')
        self.assertTrue('GTUBE' in rules, "GTUBE not found in SYMBOL scan")
        self.assertFalse(spamscore < 500)
        self.assertTrue(spamstatus)

        stream2 = """Received: from mail.python.org (mail.python.org [82.94.164.166])
    by bla.fuglu.org (Postfix) with ESMTPS id 395743E03A5
    for <recipient@unittests.fuglu.org>; Sun, 22 Aug 2010 18:15:11 +0200 (CEST)
Date: Tue, 24 Aug 2010 09:20:57 +0200
To: oli@unittests.fuglu.org
From: oli@unittests.fuglu.org
Subject: test Tue, 24 Aug 2010 09:20:57 +0200
X-Mailer: swaks v20061116.0 jetmore.org/john/code/#swaks
Message-Id: <20100824072058.282BC3E0154@fumail.leetdreams.ch>

This is a test mailing """

        spamstatus, spamscore, rules = self.candidate.safilter_symbols(
            stream2, 'oli@unittests.fuglu.org')
        # print rules
        self.assertFalse(spamstatus, "This message should not be detected as spam")

    def test_sql_blacklist(self):
        self.candidate.config.set('SAPlugin', 'check_sql_blacklist', 'True')
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', '/dev/null')

        import fuglu.extensions.sql
        if not fuglu.extensions.sql.ENABLED:
            print("Excluding test that needs sqlalchemy extension")
            return

        session = fuglu.extensions.sql.get_session(self.testdb)

        createsql = """CREATE TABLE userpref (
  username varchar(100) NOT NULL DEFAULT '',
  preference varchar(30) NOT NULL DEFAULT '',
  value varchar(100) NOT NULL DEFAULT ''
)"""

        session.execute(createsql)
        self.assertEqual(self.candidate.check_sql_blacklist(
            suspect), DUNNO), 'sender is not blacklisted'

        insertsql = """INSERT INTO userpref (username,preference,value) VALUES ('%unittests.fuglu.org','blacklist_from','*@unittests.fuglu.org')"""
        session.execute(insertsql)

        self.assertEqual(self.candidate.check_sql_blacklist(
            suspect), REJECT), 'sender should be blacklisted'

        fuglu.extensions.sql.ENABLED = False
        self.assertEqual(self.candidate.check_sql_blacklist(
            suspect), DUNNO), 'problem if sqlalchemy is not available'
        fuglu.extensions.sql.ENABLED = True

        self.candidate.config.set(
            'SAPlugin', 'sql_blacklist_sql', 'this is a buggy sql statement')
        self.assertEqual(self.candidate.check_sql_blacklist(
            suspect), DUNNO), 'error coping with db problems'

        # simulate unavailable db
        self.candidate.config.set(
            'SAPlugin', 'sql_blacklist_dbconnectstring', 'mysql://127.0.0.1:9977/idonotexist')
        self.assertEqual(self.candidate.check_sql_blacklist(
            suspect), DUNNO), 'error coping with db problems'
