from unittestsetup import TESTDATADIR
import unittest
import ConfigParser
import string
from fuglu.shared import Suspect, SuspectFilter, string_to_actioncode, actioncode_to_string, apply_template, REJECT


class SuspectTestCase(unittest.TestCase):
    """Test Suspect functions"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_id(self):
        """Check the length and uniqueness of the generated id"""
        s=Suspect('sender@example.com','recipient@example.com','/dev/null')
        known=[]
        for i in range(10000):
            suspect_id=s._generate_id()
            self.assertNotIn(suspect_id,known,'duplicate id %s generated'%suspect_id)
            known.append(suspect_id)
            self.assertEqual(len(suspect_id),32)
            for c in suspect_id:
                self.assertIn(c,string.hexdigits)


class SuspectFilterTestCase(unittest.TestCase):

    """Test Header Filter"""

    def setUp(self):
        self.candidate = SuspectFilter(TESTDATADIR + '/headertest.regex')

    def tearDown(self):
        pass

    def test_hf(self):
        """Test header filters"""

        suspect = Suspect('sender@unittests.fuglu.org',
                          'recipient@unittests.fuglu.org', TESTDATADIR + '/helloworld.eml')
        suspect.tags['testtag'] = 'testvalue'

        headermatches = self.candidate.get_args(suspect)
        self.failUnless(
            'Sent to unittest domain!' in headermatches, "To_domain not found in headercheck")
        self.failUnless('Envelope sender is sender@unittests.fuglu.org' in headermatches,
                        "Envelope Sender not matched in header chekc")
        self.failUnless('Mime Version is 1.0' in headermatches,
                        "Standard header Mime Version not found")
        self.failUnless(
            'A tag match' in headermatches, "Tag match did not work")
        self.failUnless(
            'Globbing works' in headermatches, "header globbing failed")
        self.failUnless(
            'body rule works' in headermatches, "decoded body rule failed")
        self.failUnless(
            'full body rule works' in headermatches, "full body failed")
        self.failUnless('mime rule works' in headermatches, "mime rule failed")
        self.failIf('this should not match in a body rule' in headermatches,
                    'decoded body rule matched raw body')

        # perl style advanced rules
        self.failUnless('perl-style /-notation works!' in headermatches,
                        "new rule format failed: %s" % headermatches)
        self.failUnless('perl-style recipient match' in headermatches,
                        "new rule format failed for to_domain: %s" % headermatches)
        self.failIf('this should not match' in headermatches,
                    "rule flag ignorecase was not detected")

        # TODO: raw body rules

        # extended
        (match, info) = self.candidate.matches(suspect, extended=True)
        self.failUnless(match, 'Match should return True')
        field, matchedvalue, arg, regex = info
        self.failUnless(field == 'to_domain')
        self.failUnless(matchedvalue == 'unittests.fuglu.org')
        self.failUnless(arg == 'Sent to unittest domain!')
        self.failUnless(regex == 'unittests\.fuglu\.org')


class ActionCodeTestCase(unittest.TestCase):

    def test_defaultcodes(self):
        """test actioncode<->string conversion"""
        conf = ConfigParser.ConfigParser()
        conf.add_section('spam')
        conf.add_section('virus')
        conf.set('spam', 'defaultlowspamaction', 'REJEcT')
        conf.set('spam', 'defaulthighspamaction', 'REjECT')
        conf.set('virus', 'defaultvirusaction', 'rejeCt')
        self.assertEqual(
            string_to_actioncode('defaultlowspamaction', conf), REJECT)
        self.assertEqual(
            string_to_actioncode('defaulthighspamaction', conf), REJECT)
        self.assertEqual(
            string_to_actioncode('defaultvirusaction', conf), REJECT)
        self.assertEqual(string_to_actioncode('nonexistingstuff'), None)
        self.assertEqual(actioncode_to_string(REJECT), 'REJECT')
        self.assertEqual(
            actioncode_to_string(string_to_actioncode('discard')), 'DELETE')


class TemplateTestcase(unittest.TestCase):

    """Test Templates"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_template(self):
        """Test Basic Template function"""

        suspect = Suspect('sender@unittests.fuglu.org',
                          'recipient@unittests.fuglu.org', TESTDATADIR + '/helloworld.eml')
        suspect.tags['nobounce'] = True

        reason = "a three-headed monkey stole it"

        template = """Your message '${subject}' from ${from_address} to ${to_address} could not be delivered because ${reason}"""

        result = apply_template(template, suspect, dict(reason=reason))
        expected = """Your message 'Hello world!' from sender@unittests.fuglu.org to recipient@unittests.fuglu.org could not be delivered because a three-headed monkey stole it"""
        self.assertEquals(
            result, expected), "Got unexpected template result: %s" % result


class ClientInfoTestCase(unittest.TestCase):

    """Test client info detection"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_client_info(self):
        suspect = Suspect('sender@unittests.fuglu.org',
                          'recipient@unittests.fuglu.org', TESTDATADIR + '/helloworld.eml')
        helo, ip, revdns = suspect.client_info_from_rcvd(None, 0)
        self.assertEquals(helo, 'helo1')
        self.assertEquals(ip, '10.0.0.1')
        self.assertEquals(revdns, 'rdns1')

        helo, ip, revdns = suspect.client_info_from_rcvd(None, 1)
        self.assertEquals(helo, 'helo2')
        self.assertEquals(ip, '10.0.0.2')
        self.assertEquals(revdns, 'rdns2')

        helo, ip, revdns = suspect.client_info_from_rcvd('10\.0\.0\.2', 1)
        self.assertEquals(helo, 'helo3')
        self.assertEquals(ip, '10.0.0.3')
        self.assertEquals(revdns, 'rdns3')
