from integrationtestsetup import guess_clamav_socket, TESTDATADIR, CONFDIR, DummySMTPServer
import unittest
import tempfile
import os
import thread
import time
import smtplib
import mock
from email.mime.text import MIMEText

try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput

import fuglu
from fuglu.lib.patcheddkimlib import verify, sign
from fuglu.core import MainController
from fuglu.scansession import SessionHandler


class AllpluginTestCase(unittest.TestCase):

    """Tests that pass with a default config"""

    def setUp(self):
        config = RawConfigParser()
        config.read([CONFDIR + '/fuglu.conf.dist'])
        config.set('main', 'disablebounces', '1')
        guess_clamav_socket(config)

        self.mc = MainController(config)
        self.tempfiles = []

    def tearDown(self):
        for tempfile in self.tempfiles:
            os.remove(tempfile)

    def test_virus(self):
        """Test if eicar is detected as virus"""
        from fuglu.shared import Suspect
        import shutil

        self.mc.load_plugins()
        if len(self.mc.plugins) == 0:
            raise Exception("plugins not loaded")

        sesshandler = SessionHandler(
            None, self.mc.config, self.mc.prependers, self.mc.plugins, self.mc.appenders)
        tempfilename = tempfile.mktemp(
            suffix='virus', prefix='fuglu-unittest', dir='/tmp')
        shutil.copy(TESTDATADIR + '/eicar.eml', tempfilename)
        self.tempfiles.append(tempfilename)
        suspect = Suspect(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', tempfilename)
        pluglist = sesshandler.run_prependers(suspect)
        self.assertFalse(
            len(pluglist) == 0, "Viruscheck will fail, pluginlist empty after run_prependers")
        sesshandler.run_plugins(suspect, pluglist)
        self.assertTrue(
            suspect.is_virus(), "Eicar message was not detected as virus")


class EndtoEndTestTestCase(unittest.TestCase):

    """Full check if mail runs through"""

    FUGLU_HOST = "127.0.0.1"
    FUGLU_PORT = 7711
    DUMMY_PORT = 7712
    FUGLUCONTROL_PORT = 7713

    def setUp(self):
        self.config = RawConfigParser()
        self.config.read([TESTDATADIR + '/endtoendtest.conf'])
        self.config.set(
            'main', 'incomingport', str(EndtoEndTestTestCase.FUGLU_PORT))
        self.config.set(
            'main', 'outgoinghost', str(EndtoEndTestTestCase.FUGLU_HOST))
        self.config.set(
            'main', 'outgoingport', str(EndtoEndTestTestCase.DUMMY_PORT))
        self.config.set(
            'main', 'controlport', str(EndtoEndTestTestCase.FUGLUCONTROL_PORT))
        guess_clamav_socket(self.config)
        # init core
        self.mc = MainController(self.config)

        # start listening smtp dummy server to get fuglus answer
        self.smtp = DummySMTPServer(
            self.config, EndtoEndTestTestCase.DUMMY_PORT, EndtoEndTestTestCase.FUGLU_HOST)
        thread.start_new_thread(self.smtp.serve, ())

        # start fuglus listening server
        thread.start_new_thread(self.mc.startup, ())

    def tearDown(self):
        self.mc.shutdown()
        self.smtp.shutdown()

    def testE2E(self):
        """test if a standard message runs through"""

        # give fuglu time to start listener
        time.sleep(1)

        # send test message
        smtpclient = smtplib.SMTP('127.0.0.1', EndtoEndTestTestCase.FUGLU_PORT)
        # smtpServer.set_debuglevel(1)
        smtpclient.helo('test.e2e')
        testmessage = """Hello World!\r
Don't dare you change any of my bytes or even remove one!"""

        # TODO: this test fails if we don't put in the \r in there... (eg,
        # fuglu adds it) - is this a bug or wrong test?

        msg = MIMEText(testmessage)
        msg["Subject"] = "End to End Test"
        msgstring = msg.as_string()
        inbytes = len(msg.get_payload())
        smtpclient.sendmail(
            'sender@fuglu.org', 'recipient@fuglu.org', msgstring)
        smtpclient.quit()

        # get answer
        gotback = self.smtp.suspect
        self.assertFalse(
            gotback == None, "Did not get message from dummy smtp server")

        # check a few things on the received message
        msgrep = gotback.get_message_rep()
        self.assertTrue('X-Fuglutest-Spamstatus' in msgrep, "Fuglu SPAM Header not found in message")
        payload = msgrep.get_payload()
        outbytes = len(payload)
        self.assertEqual(testmessage, payload, "Message body has been altered. In: %s bytes, Out: %s bytes, teststring=->%s<- result=->%s<-" %
                             (inbytes, outbytes, testmessage, payload))


class DKIMTestCase(unittest.TestCase):

    """DKIM Sig Test"""

    FUGLU_HOST = "127.0.0.1"
    FUGLU_PORT = 7731
    DUMMY_PORT = 7732
    FUGLUCONTROL_PORT = 7733

    def setUp(self):

        k = ''
        for line in open(TESTDATADIR + '/dkim/testfuglu.org.public'):
            if line.startswith('---'):
                continue
            k = k + line.strip()
        record = "v=DKIM1; k=rsa; p=%s" % k
        fuglu.lib.patcheddkimlib.dnstxt = mock.Mock(return_value=record)

        self.config = RawConfigParser()
        self.config.read([TESTDATADIR + '/endtoendtest.conf'])
        self.config.set('main', 'incomingport', str(DKIMTestCase.FUGLU_PORT))
        self.config.set('main', 'outgoinghost', str(DKIMTestCase.FUGLU_HOST))
        self.config.set('main', 'outgoingport', str(DKIMTestCase.DUMMY_PORT))
        self.config.set(
            'main', 'controlport', str(DKIMTestCase.FUGLUCONTROL_PORT))
        guess_clamav_socket(self.config)

        # init core
        self.mc = MainController(self.config)

        # start listening smtp dummy server to get fuglus answer
        self.smtp = DummySMTPServer(self.config, self.config.getint(
            'main', 'outgoingport'), DKIMTestCase.FUGLU_HOST)
        thread.start_new_thread(self.smtp.serve, ())

        # start fuglus listening server
        thread.start_new_thread(self.mc.startup, ())

    def tearDown(self):
        self.mc.shutdown()
        self.smtp.shutdown()

    def testDKIM(self):
        # give fuglu time to start listener
        time.sleep(1)
        inputfile = TESTDATADIR + '/helloworld.eml'
        msgstring = open(inputfile, 'r').read()

        dkimheader = sign(msgstring, 'whatever', 'testfuglu.org', open(
            TESTDATADIR + '/dkim/testfuglu.org.private').read(), include_headers=['From', 'To'])
        signedcontent = dkimheader + msgstring
        logbuffer = StringIO()
        self.assertTrue(verify(signedcontent, debuglog=logbuffer),
                        "Failed DKIM verification immediately after signing %s" % logbuffer.getvalue())

        # send test message
        try:
            smtpclient = smtplib.SMTP('127.0.0.1', DKIMTestCase.FUGLU_PORT)
        except Exception as e:
            self.fail("Could not connect to fuglu on port %s : %s" %
                      (DKIMTestCase.FUGLU_PORT, str(e)))
        # smtpServer.set_debuglevel(1)
        smtpclient.helo('test.dkim')

        smtpclient.sendmail(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', signedcontent)

        smtpclient.quit()

        # verify the smtp server stored the file correctly
        tmpfile = self.smtp.tempfilename
        self.assertTrue(tmpfile != None, 'Send to dummy smtp server failed')

        result = open(tmpfile, 'r').read()
        logbuffer = StringIO()
        verify_ok = verify(result, debuglog=logbuffer)
        self.assertTrue(
            verify_ok, "Failed DKIM verification: %s" % logbuffer.getvalue())


class SMIMETestCase(unittest.TestCase):

    """Email Signature Tests"""

    FUGLU_HOST = "127.0.0.1"
    FUGLU_PORT = 7721
    DUMMY_PORT = 7722
    FUGLUCONTROL_PORT = 7723

    def setUp(self):
        time.sleep(5)
        self.config = RawConfigParser()
        self.config.read([TESTDATADIR + '/endtoendtest.conf'])
        self.config.set('main', 'incomingport', str(SMIMETestCase.FUGLU_PORT))
        self.config.set('main', 'outgoinghost', str(SMIMETestCase.FUGLU_HOST))
        self.config.set('main', 'outgoingport', str(SMIMETestCase.DUMMY_PORT))
        self.config.set(
            'main', 'controlport', str(SMIMETestCase.FUGLUCONTROL_PORT))
        guess_clamav_socket(self.config)

        # init core
        self.mc = MainController(self.config)

        # start listening smtp dummy server to get fuglus answer
        self.smtp = DummySMTPServer(
            self.config, SMIMETestCase.DUMMY_PORT, SMIMETestCase.FUGLU_HOST)
        thread.start_new_thread(self.smtp.serve, ())

        # start fuglus listening server
        thread.start_new_thread(self.mc.startup, ())

    def tearDown(self):
        self.mc.shutdown()
        self.smtp.shutdown()

    def testSMIME(self):
        """test if S/MIME mails still pass the signature"""

        # give fuglu time to start listener
        time.sleep(1)

        # send test message
        smtpclient = smtplib.SMTP('127.0.0.1', SMIMETestCase.FUGLU_PORT)
        # smtpServer.set_debuglevel(1)
        smtpclient.helo('test.smime')
        inputfile = TESTDATADIR + '/smime/signedmessage.eml'
        (status, output) = self.verifyOpenSSL(inputfile)
        self.assertTrue(
            status == 0, "Testdata S/MIME verification failed: \n%s" % output)
        msgstring = open(inputfile, 'r').read()
        smtpclient.sendmail(
            'sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', msgstring)

        smtpclient.quit()

        # verify the smtp server stored the file correctly
        tmpfile = self.smtp.tempfilename

        #self.failUnlessEqual(msgstring, tmpcontent, "SMTP Server did not store the tempfile correctly: %s"%tmpfile)
        (status, output) = self.verifyOpenSSL(tmpfile)
        self.assertTrue(
            status == 0, "S/MIME verification failed: \n%s\n tmpfile is:%s" % (output, tmpfile))

    def verifyOpenSSL(self, file):
        (status, output) = getstatusoutput(
            "openssl smime -verify -noverify -in %s" % file)
        return (status, output)
