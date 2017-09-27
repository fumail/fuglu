import unittest
import unittestsetup

from fuglu.shared import Suspect, DUNNO, REJECT
from fuglu.plugins.domainauth import SPFPlugin, SpearPhishPlugin
try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser
import tempfile
import os

class SPFTestCase(unittest.TestCase):

    """SPF Check Tests"""

    def _make_dummy_suspect(self, senderdomain, clientip, helo='foo.example.com'):
        s = Suspect('sender@%s' %
                    senderdomain, 'recipient@example.com', '/dev/null')
        s.clientinfo = (helo, clientip, 'ptr.example.com')
        return s

    def setUp(self):
        self.candidate = SPFPlugin(None)

    def tearDown(self):
        pass

    def testSPF(self):
        # TODO: for now we use gmail.com as spf test domain with real dns
        # lookups - replace with mock

        # google fail test

        suspect = self._make_dummy_suspect('gmail.com', '1.2.3.4')
        self.candidate.examine(suspect)
        self.assertEquals(suspect.get_tag('SPF.status'), 'softfail')

        suspect = self._make_dummy_suspect('gmail.com', '216.239.32.22')
        self.candidate.examine(suspect)
        self.assertEquals(suspect.get_tag('SPF.status'), 'pass')

        # no spf record
        suspect = self._make_dummy_suspect('unittests.fuglu.org', '1.2.3.4')
        self.candidate.examine(suspect)
        self.assertEqual(suspect.get_tag('SPF.status'), 'none')


class SpearPhishTestCase(unittest.TestCase):
    """Spearphish Plugin Tests"""

    def _make_dummy_suspect(self, envelope_sender_domain='a.unittests.fuglu.org', header_from_domain='a.unittests.fuglu.org', recipient_domain='b.unittests.fuglu.org', file='/dev/null'):
        s = Suspect('sender@%s' %
                    envelope_sender_domain, 'recipient@%s'%recipient_domain, file)

        template="""From: sender@%s
Subject: Hello spear phished world!
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_12140"

------=_MIME_BOUNDARY_000_12140
Content-Type: text/plain

blablabla

some <tagged>text</tagged>
------=_MIME_BOUNDARY_000_12140--
        """%header_from_domain

        s.set_source(template)
        return s

    def _make_config(self, checkdomains=None, virusname='UNITTEST-SPEARPHISH', virusaction='REJECT', virusenginename='UNIITEST Spearphishing protection', rejectmessage='threat detected: ${virusname}', check_display_part='True' ):
        config = RawConfigParser()
        config.add_section('SpearPhishPlugin')

        if checkdomains:
            tempfilename = tempfile.mktemp(
                suffix='spearphish', prefix='fuglu-unittest', dir='/tmp')
            fp = open(tempfilename, 'w')
            fp.write('\n'.join(checkdomains))
            self.tempfiles.append(tempfilename)
            config.set('SpearPhishPlugin', 'domainsfile', tempfilename)
        else:
            config.set('SpearPhishPlugin', 'domainsfile', '')
        config.set('SpearPhishPlugin', 'virusname', virusname)
        config.set('SpearPhishPlugin', 'virusaction', virusaction)
        config.set('SpearPhishPlugin', 'virusenginename', virusenginename)
        config.set('SpearPhishPlugin', 'rejectmessage', rejectmessage)
        config.set('SpearPhishPlugin', 'dbconnection', '')
        config.set('SpearPhishPlugin', 'domain_sql_query', '')
        config.set('SpearPhishPlugin', 'check_display_part', check_display_part)
        return config


    def setUp(self):
        self.tempfiles = []


    def tearDown(self):
        for tempfile in self.tempfiles:
            os.remove(tempfile)

    def test_check_specific_domains(self):
        """Test if only domains from the config file get checked"""
        shouldcheck = ['evil1.unittests.fuglu.org', 'evil2.unittests.fuglu.org']
        shouldnotcheck = ['evil11.unittests.fuglu.org', 'evil22.unittests.fuglu.org']

        config = self._make_config(checkdomains=shouldcheck, virusaction='REJECT', rejectmessage='spearphish')
        candidate = SpearPhishPlugin(None)
        candidate.config = config

        for domain in shouldcheck:
            suspect = self._make_dummy_suspect(envelope_sender_domain='example.com', recipient_domain=domain, header_from_domain=domain)
            self.assertEqual(candidate.examine(suspect), (REJECT, 'spearphish'), ' spearphish should have been detected')

        for domain in shouldnotcheck:
            suspect = self._make_dummy_suspect(envelope_sender_domain='example.com', recipient_domain=domain,
                                               header_from_domain=domain)
            self.assertEqual(candidate.examine(suspect), DUNNO, 'spearphish should have been ignored - not in config file' )

    def test_check_all_domains(self):
        """Test if all domains are checked if an empty file is configured"""
        shouldcheck = ['evil1.unittests.fuglu.org', 'evil2.unittests.fuglu.org']

        config = self._make_config(checkdomains=[], virusaction='REJECT', rejectmessage='spearphish')
        candidate = SpearPhishPlugin(None)
        candidate.config = config

        for domain in shouldcheck:
            suspect = self._make_dummy_suspect(envelope_sender_domain='example.com', recipient_domain=domain,
                                               header_from_domain=domain)
            self.assertEqual(candidate.examine(suspect), (REJECT, 'spearphish'),
                             ' spearphish should have been detected')


    def test_specification(self):
        """Check if the plugin works as intended:
        Only hit if header_from_domain = recipient domain but different envelope sender domain
        """
        config = self._make_config(checkdomains=[], virusaction='REJECT', rejectmessage='spearphish')
        candidate = SpearPhishPlugin(None)
        candidate.config = config

        # the spearphish case, header from = recipient, but different env sender
        self.assertEqual(candidate.examine(
            self._make_dummy_suspect(
                envelope_sender_domain='a.example.com',
                recipient_domain='b.example.com',
                header_from_domain='b.example.com')),
            (REJECT, 'spearphish'),
            'spearphish should have been detected')

        # don't hit if env sender matches as well
        self.assertEqual(candidate.examine(
            self._make_dummy_suspect(
                envelope_sender_domain='c.example.com',
                recipient_domain='c.example.com',
                header_from_domain='c.example.com')),
            DUNNO,
            'env sender domain = recipient domain should NOT be flagged as spearphish (1)')

        # don't hit if all different
        self.assertEqual(candidate.examine(
            self._make_dummy_suspect(
                envelope_sender_domain='d.example.com',
                recipient_domain='e.example.com',
                header_from_domain='f.example.com')),
            DUNNO,
            'env sender domain = recipient domain should NOT be flagged as spearphish (2)')
