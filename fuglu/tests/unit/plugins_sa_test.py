from unittestsetup import TESTDATADIR

import unittest
import tempfile
import os

try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

from fuglu.plugins.sa import SAPlugin
from fuglu.shared import Suspect
from email.message import Message
from email.header import Header


class SATestCase(unittest.TestCase):

    def setUp(self):
        config = RawConfigParser()
        config.add_section('main')
        config.set('main', 'disablebounces', '1')
        config.add_section('SAPlugin')
        # current tests don't need config options, add them here later if
        # necessary
        self.config = config

    def tearDown(self):
        pass

    def test_extract_spamstatus(self):
        """Test if the spam status header gets extracted correctly"""

        candidate = SAPlugin(self.config)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', '/dev/null')
        headername = 'X-Spam-Status'
        headertests = [  # tuple header content, expected spamstatus, expected spam score
            ('YES', True, None),  # _YESNOCAPS_
            ('NO', False, None),  # _YESNOCAPS_
            (' Yes, score=13.37', True, 13.37),  # _YESNO_, score=_SCORE_
            (' No, score=-2.826', False, -2.826),  # _YESNO_, score=_SCORE_
            # with test names, bug #24
            ("No, score=1.9 required=8.0 tests=BAYES_00,FROM_EQ_TO,TVD_SPACE_RATIO,TVD_SPACE_RATIO_MINFP autolearn=no autolearn_force=no version=3.4.0",
             False, 1.9),
        ]

        for headercontent, expectedspamstatus, expectedscore in headertests:
            msgrep = Message()
            msgrep[headername] = Header(headercontent).encode()
            spamstatus, score, report = candidate._extract_spamstatus(
                msgrep, headername, suspect)
            self.assertEqual(spamstatus, expectedspamstatus, "spamstatus should be %s from %s" % (
                expectedspamstatus, headercontent))
            self.assertEqual(score, expectedscore, "spamscore should be %s from %s" % (
                expectedscore, headercontent))
