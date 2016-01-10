# -*- coding: utf-8 -*-
import unittestsetup
import fuglu
import unittest
from datetime import datetime, timedelta

from fuglu.plugins.vacation import VacationPlugin, VacationCache, Vacation, metadata


class VacationTestCase(unittest.TestCase):

    """Testcases for the Stub Plugin"""

    def setUp(self):
        import os
        try:
            from configparser import RawConfigParser
        except ImportError:
            from ConfigParser import RawConfigParser
        testfile = "/tmp/vacation_test.db"
        if os.path.exists(testfile):
            os.remove(testfile)
        # important: 4 slashes for absolute paths!
        testdb = "sqlite:///%s" % testfile

        config = RawConfigParser()
        config.add_section('VacationPlugin')
        config.set('VacationPlugin', 'dbconnectstring', testdb)
        self.config = config
        self.candidate = VacationPlugin(config)

        self.session = fuglu.extensions.sql.get_session(testdb)
        bind = self.session.get_bind(Vacation)
        self.create_database(bind)

    def create_database(self, engine):
        #engine.echo = True
        con = engine.connect()
        metadata.create_all(engine)

    def refreshcache(self):
        cache = VacationCache(self.config)
        cache._loadvacation()

    def test_lint(self):
        """Test basic lint"""
        self.assertTrue(self.candidate.lint())

    def test_vacation(self):
        """Test simple vacation use case"""
        from fuglu.shared import Suspect
        v = Vacation()
        v.ignoresender = ""
        v.awayuser = u'recipient@unittests.fuglu.org'
        v.created = datetime.now()
        v.start = datetime.now()
        v.end = v.start + timedelta(days=2)
        v.subject = u'awaaay'
        v.body = u'cya'
        self.session.add(v)
        self.session.flush()
        self.session.expunge_all()
        self.refreshcache()
        suspect = Suspect(
            u'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', '/dev/null')
        suspect.set_tag('nobounce', True)

        candidatevacation = self.candidate.on_vacation(suspect)
        self.assertTrue(
            candidatevacation != None, "Vacation object not found in database")
        self.assertTrue(self.candidate.should_send_vacation_message(
            suspect), "Test Message should generate vacation reply")
        self.candidate.log_bounce(suspect, candidatevacation)

        # TODO: had to disable due to sqlalchemy error
        # Instance <Vacation at 0x2938890> is not bound to a Session; attribute refresh operation cannot proceed
        #self.assertFalse(self.candidate.should_send_vacation_message(suspect),"2nd test Message should NOT generate vacation reply")

        suspect2 = Suspect(
            u'sender@unittests.fuglu.org', 'recipient2@unittests.fuglu.org', '/dev/null')
        suspect2.set_tag('nobounce', True)
        candidatevacation = self.candidate.on_vacation(suspect2)
        self.assertFalse(candidatevacation != None,
                         "There should be no vacation object for this recipient")
        self.assertFalse(self.candidate.should_send_vacation_message(
            suspect2), "test Message should NOT generate vacation reply")

    def test_ignore_sender(self):
        from fuglu.shared import Suspect
        v = Vacation()
        v.ignoresender = u"unittests.fuglu.org oli@wgwh.ch"
        v.awayuser = u'recipient@unittests.fuglu.org'
        v.created = datetime.now()
        v.start = datetime.now()
        v.end = v.start + timedelta(days=2)
        v.subject = u'gone for good'
        v.body = u'outta here'
        self.session.add(v)
        self.session.flush()
        self.session.expunge_all()
        self.refreshcache()
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', '/dev/null')
        suspect.set_tag('nobounce', True)

        candidatevacation = self.candidate.on_vacation(suspect)
        self.assertTrue(
            candidatevacation != None, "Vacation object not found in database")
        # TODO had to disable due to sqlalchemy error
        # Instance <Vacation at 0x2938890> is not bound to a Session; attribute refresh operation cannot proceed
        #self.assertEqual(v.ignoresender,candidatevacation.ignoresender,"Vacation object did not get ignore list")
        self.assertTrue(self.candidate.ignore_sender(
            candidatevacation, suspect), "Test Message should generate vacation reply(ignored sender)")
        self.assertFalse(self.candidate.should_send_vacation_message(
            suspect), "Sender on ignorelist, still wants to send message?!")

    def test_header(self):
        from fuglu.shared import Suspect
        import email
        v = Vacation()
        v.ignoresender = u""
        v.awayuser = u'recipient@unittests.fuglu.org'
        v.created = datetime.now()
        v.start = datetime.now()
        v.end = v.start + timedelta(days=2)
        v.subject = u'awaaay'
        v.body = u'cya'
        self.session.add(v)
        self.session.flush()
        self.session.expunge_all()
        self.refreshcache()
        botmsg = """From: sender@unittests.fuglu.org
Precedence: Junk
Subject: mailinglist membership reminder...
"""

        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', '/dev/null')
        suspect.set_tag('nobounce', True)
        suspect.set_source(botmsg)

        candidatevacation = self.candidate.on_vacation(suspect)
        self.assertTrue(
            candidatevacation != None, "Vacation object not found in database")
        self.assertFalse(self.candidate.should_send_vacation_message(
            suspect), "Test Message should NOT generate vacation reply(automated)")

    def test_localpartblacklist(self):
        """test messages from mailer-daemon"""
        from fuglu.shared import Suspect
        import email
        v = Vacation()
        v.ignoresender = u""
        v.awayuser = u'recipient@unittests.fuglu.org'
        v.created = datetime.now()
        v.start = datetime.now()
        v.end = v.start + timedelta(days=2)
        v.subject = u'awaaay'
        v.body = u'cya'
        self.session.add(v)
        self.session.flush()
        self.session.expunge_all()
        self.refreshcache()
        botmsg = """From: sender@unittests.fuglu.org
Subject: mailinglist membership reminder...
"""

        suspect = Suspect('MAILER-daEmon@unittests.fuglu.org',
                          'recipient@unittests.fuglu.org', '/dev/null')
        suspect.set_tag('nobounce', True)
        suspect.set_source(botmsg)

        candidatevacation = self.candidate.on_vacation(suspect)
        self.assertTrue(
            candidatevacation != None, "Vacation object not found in database")
        self.assertFalse(self.candidate.should_send_vacation_message(
            suspect), "Test Message should NOT generate vacation reply(automated)")

    def test_generated_message(self):
        from fuglu.shared import Suspect
        suspect = Suspect(
            u'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', '/dev/null')
        suspect.tags['nobounce'] = True

        v = Vacation()
        v.ignoresender = u""
        v.awayuser = u'recipient@unittests.fuglu.org'
        v.created = datetime.now()
        v.start = datetime.now()
        v.end = v.start + timedelta(days=2)
        v.subject = u'Döner mit schärf!'
        v.body = u"""Je m'envole pour l'Allemagne, où je suis né."""
        # v.body="Away!"
        self.session.add(v)
        self.session.flush()
        self.session.expunge_all()
        self.refreshcache()

        candidatevacation = self.candidate.on_vacation(suspect)
        self.assertTrue(
            candidatevacation != None, "Vacation object not found in database")

        message = self.candidate.send_vacation_reply(
            suspect, candidatevacation)
