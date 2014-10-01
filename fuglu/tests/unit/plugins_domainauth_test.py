import unittest
import unittestsetup

from fuglu.shared import Suspect
from fuglu.plugins.domainauth import SPFPlugin

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

        # google accept test
        suspect = self._make_dummy_suspect('gmail.com', '216.239.32.22')
        self.candidate.examine(suspect)
        self.assertEquals(suspect.get_tag('SPF.status'), 'pass')

        # no spf record
        suspect = self._make_dummy_suspect('fuglu.org', '1.2.3.4')
        self.candidate.examine(suspect)
        self.assertEquals(suspect.get_tag('SPF.status'), 'none')