from unittestsetup import TESTDATADIR, CONFDIR

import unittest
import os
from ConfigParser import RawConfigParser

from fuglu.shared import Suspect
from fuglu.extensions.sql import get_session, DBConfig


class DBConfigTestCase(unittest.TestCase):

    """Test Templates"""

    def setUp(self):
        self.testfile = "/tmp/fuglu_override_test.db"
        if os.path.exists(self.testfile):
            os.remove(self.testfile)
        # important: 4 slashes for absolute paths!
        self.testdb = "sqlite:///%s" % self.testfile

        config = RawConfigParser()
        config.add_section('databaseconfig')
        config.set('databaseconfig', 'dbconnectstring', self.testdb)
        config.set('databaseconfig', "sql",
                   "SELECT value FROM fugluconfig WHERE section=:section AND option=:option AND scope IN ('$GLOBAL','%'||:to_domain,:to_address) ORDER BY SCOPE DESC")
        self.config = config
        self.create_database()

    def create_database(self):
        sql = """
        CREATE TABLE fugluconfig (
           scope varchar(255) NOT NULL,
           section varchar(255) NOT NULL,
           option varchar(255) NOT NULL,
           value varchar(255) NOT NULL
        )
        """
        self.exec_sql(sql)

    def clear_table(self):
        self.exec_sql("DELETE FROM fugluconfig")

    def exec_sql(self, sql, values=None):
        if values == None:
            values = {}
        session = get_session(self.testdb)
        session.execute(sql, values)
        session.remove()

    def insert_override(self, scope, section, option, value):
        sql = "INSERT INTO fugluconfig (scope,section,option,value) VALUES (:scope,:section,:option,:value)"
        values = dict(scope=scope, section=section, option=option, value=value)
        self.exec_sql(sql, values)

    def tearDown(self):
        os.remove(self.testfile)

    def test_user_override(self):
        """Test basic config overrdide functionality"""
        suspect = Suspect(
            u'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', '/dev/null')

        candidate = DBConfig(self.config, suspect)

        candidate.add_section('testsection')
        candidate.set('testsection', 'nooverride', '100')
        candidate.set('testsection', 'override', '100')

        self.clear_table()
        self.insert_override(
            'recipient@unittests.fuglu.org', 'testsection', 'override', '200')
        self.insert_override(
            '%unittests.fuglu.org', 'testsection', 'override', '300')
        self.insert_override('$GLOBAL', 'testsection', 'override', '400')
        self.assertEqual(candidate.getint('testsection', 'nooverride'), 100)
        self.assertEqual(candidate.getint('testsection', 'override'), 200)

    def test_domain_override(self):
        """Test basic config overrdide functionality"""
        suspect = Suspect(
            u'sender@unittests.fuglu.org', 'someotherrec@unittests.fuglu.org', '/dev/null')

        candidate = DBConfig(self.config, suspect)

        candidate.add_section('testsection')
        candidate.set('testsection', 'nooverride', '100')
        candidate.set('testsection', 'override', '100')

        self.clear_table()
        self.insert_override(
            'recipient@unittests.fuglu.org', 'testsection', 'override', '200')
        self.insert_override(
            '%unittests.fuglu.org', 'testsection', 'override', '300')
        self.insert_override('$GLOBAL', 'testsection', 'override', '400')
        self.assertEqual(candidate.getint('testsection', 'nooverride'), 100)
        self.assertEqual(candidate.getint('testsection', 'override'), 300)

    def test_global_override(self):
        """Test basic config overrdide functionality"""
        suspect = Suspect(
            u'sender@unittests.fuglu.org', 'someotherrec@unittests2.fuglu.org', '/dev/null')

        candidate = DBConfig(self.config, suspect)

        candidate.add_section('testsection')
        candidate.set('testsection', 'nooverride', '100')
        candidate.set('testsection', 'override', '100')

        self.clear_table()
        self.insert_override(
            'recipient@unittests.fuglu.org', 'testsection', 'override', '200')
        self.insert_override(
            '%unittests.fuglu.org', 'testsection', 'override', '300')
        self.insert_override('$GLOBAL', 'testsection', 'override', '400')
        self.assertEqual(candidate.getint('testsection', 'nooverride'), 100)
        self.assertEqual(candidate.getint('testsection', 'override'), 400)
