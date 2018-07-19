# -*- coding: UTF-8 -*-
from integrationtestsetup import TESTDATADIR, CONFDIR, DummySMTPServer
import unittest
import os
import threading
import time

try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

from fuglu.bounce import Bounce
from fuglu.shared import Suspect, apply_template
from fuglu.stringencode import force_bString

class BounceEnd2EndTestCase(unittest.TestCase):

    """Full check if mail runs through"""

    FUGLU_HOST = "127.0.0.1"
    DUMMY_PORT = 7712

    def setUp(self):
        self.config = RawConfigParser()
        self.config.read([TESTDATADIR + '/endtoendtest.conf'])
        self.config.set(
            'main', 'outgoinghost', str(BounceEnd2EndTestCase.FUGLU_HOST))
        self.config.set(
            'main', 'outgoingport', str(BounceEnd2EndTestCase.DUMMY_PORT))
        self.config.set('main', 'disablebounces',str(0))

        # start listening smtp dummy server to get bounce answer
        self.smtp = DummySMTPServer(
            self.config, BounceEnd2EndTestCase.DUMMY_PORT, BounceEnd2EndTestCase.FUGLU_HOST)
        self.e2edss = threading.Thread(target = self.smtp.serve, args = ())
        self.e2edss.daemon = True
        self.e2edss.start()

    def tearDown(self):
        self.smtp.shutdown()
        self.e2edss.join()


    def test_bounce(self):
        """Test bounce message, especially the encoding"""
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', '/dev/null')

        # include non-ascii charset unicode characters to make sure the encoding/decoding
        # works correctly
        displayname = u"((testing placeholder for displayname -> äää))"
        asciirep    = u"((testing placeholder for asciirep -> üüü))"
        description = u"((testing placeholder for description -> ööö))"

        blockinfo = ("%s %s: %s" % (displayname, asciirep, description)).strip()
        blockedfiletemplate = os.path.join(*[CONFDIR,"templates","blockedfile.tmpl.dist"])

        bounce = Bounce(self.config)
        bounce.send_template_file(
            suspect.from_address, blockedfiletemplate, suspect, dict(blockinfo=blockinfo))

        # might be needed to wait for a bit to make sure answer is available
        counter = 0
        while self.smtp.suspect is None and counter < 20:
            counter = counter + 1
            time.sleep(0.05) # sleep is needed to

        gotback = self.smtp.suspect
        self.assertFalse(
            gotback == None, "Did not get message from dummy smtp server")

        # get message received by dummy smtp server
        msg = gotback.get_message_rep()
        receivedMsg = msg.get_payload(decode='utf-8')

        # Build the message according to what Bounce is doing so it can be compared
        # to what was received from DummySMTPServer
        with open(blockedfiletemplate) as fp:
            templatecontent = fp.read()

        blockinfo = ("%s %s: %s" % (displayname, asciirep, description)).strip()
        message = apply_template(templatecontent, suspect, dict(blockinfo=blockinfo))
        messageB = force_bString(message)

        # modify received message to add header parts from template
        messageToCompare = force_bString("To: "+msg['To']+"\nSubject: "+msg['Subject']+"\n\n")+force_bString(receivedMsg)

        # make sure comparison will not fail because of newlines
        # For example, Python 2.6 has only one "\n" at the end of the received message, whereas Python 2.7 and 3 have to
        messageToCompare = messageToCompare.replace(b"\r",b"\n").replace(b"\n\n",b"\n")
        messageB = messageB.replace(b"\r",b"\n").replace(b"\n\n",b"\n")

        self.assertEqual(messageB,messageToCompare)
