from unittestsetup import TESTDATADIR
import unittest
import string
from fuglu.shared import Suspect, SuspectFilter, string_to_actioncode, actioncode_to_string, apply_template, REJECT, FileList
from fuglu.addrcheck import Default, LazyQuotedLocalPart
import os

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser


class SuspectTestCase(unittest.TestCase):

    """Test Suspect functions"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_id(self):
        """Check the length and uniqueness of the generated id"""
        s = Suspect('sender@example.com', 'recipient@example.com', '/dev/null')
        known = []
        for i in range(10000):
            suspect_id = s._generate_id()
            self.assertTrue(
                suspect_id not in known, 'duplicate id %s generated' % suspect_id)
            known.append(suspect_id)
            self.assertEqual(len(suspect_id), 32)
            for c in suspect_id:
                self.assertTrue(c in string.hexdigits)

    def test_from_to_parsing(self):
        s = Suspect('sender@example.com', 'recipient@example.com', '/dev/null')

        self.assertEqual("sender@example.com", s.from_address)
        self.assertEqual("sender", s.from_localpart)
        self.assertEqual("example.com", s.from_domain)

        self.assertEqual("recipient@example.com", s.to_address)
        self.assertEqual("recipient", s.to_localpart)
        self.assertEqual("example.com", s.to_domain)

        for sender in (None, ''):
            s = Suspect(sender, 'recipient@example.com', '/dev/null')
            self.assertEqual("", s.from_address)
            self.assertEqual("", s.from_localpart)
            self.assertEqual("", s.from_domain)

            self.assertEqual("recipient@example.com", s.to_address)
            self.assertEqual("recipient", s.to_localpart)
            self.assertEqual("example.com", s.to_domain)

    def test_from_to_local_addr(self):
        """Make sure local senders / recipients are accepted"""
        s = Suspect('bob@localhost', 'root@localhost', '/dev/null')
        self.assertEqual("bob@localhost", s.from_address)
        self.assertEqual("bob", s.from_localpart)
        self.assertEqual("localhost", s.from_domain)

        self.assertEqual("root@localhost", s.to_address)
        self.assertEqual("root", s.to_localpart)
        self.assertEqual("localhost", s.to_domain)


    def test_from_to_illegal(self):
        """Make sure invalid sender/recipient addresses raise a ValueError"""
        self.assertRaises(ValueError, Suspect, "sender@example.com", None, '/dev/null')
        self.assertRaises(ValueError, Suspect, "sender@example.com", "recipient", '/dev/null')
        self.assertRaises(ValueError, Suspect, "sender", "recipient@example.com", '/dev/null')
        self.assertRaises(ValueError, Suspect, "sender@example.net", "recipient@example.com@example.org", '/dev/null')

    def test_special_local_part(self):
        """Make sure Sender/Receiver with quoted local part are received correctly and can contain '@'"""
        Suspect.addrIsLegitimate = Default()
        self.assertRaises(ValueError, Suspect, "sender@example.net", "recipient@example.com@example.org", '/dev/null')

        Suspect.addrIsLegitimate = LazyQuotedLocalPart()
        s = Suspect('"bob@remotehost"@localhost', "'root@localhost'@remotehost", '/dev/null')
        self.assertEqual('"bob@remotehost"@localhost', s.from_address)
        self.assertEqual('"bob@remotehost"', s.from_localpart)
        self.assertEqual("localhost", s.from_domain)

        self.assertEqual("'root@localhost'@remotehost", s.to_address)
        self.assertEqual("'root@localhost'", s.to_localpart)
        self.assertEqual("remotehost", s.to_domain)

class SuspectFilterTestCase(unittest.TestCase):

    """Test Suspectfilter"""

    def setUp(self):
        self.candidate = SuspectFilter(TESTDATADIR + '/headertest.regex')

    def tearDown(self):
        pass

    def test_sf_get_args(self):
        """Test SuspectFilter files"""
        suspect = Suspect('sender@unittests.fuglu.org',
                          'recipient@unittests.fuglu.org', TESTDATADIR + '/helloworld.eml')
        suspect.tags['testtag'] = 'testvalue'

        headermatches = self.candidate.get_args(suspect)
        self.assertTrue(
            'Sent to unittest domain!' in headermatches, "To_domain not found in headercheck")
        self.assertTrue('Envelope sender is sender@unittests.fuglu.org' in headermatches,
                        "Envelope Sender not matched in header chekc")
        self.assertTrue('Mime Version is 1.0' in headermatches,
                        "Standard header Mime Version not found")
        self.assertTrue(
            'A tag match' in headermatches, "Tag match did not work")
        self.assertTrue(
            'Globbing works' in headermatches, "header globbing failed")
        self.assertTrue(
            'body rule works' in headermatches, "decoded body rule failed")
        self.assertTrue(
            'full body rule works' in headermatches, "full body failed")
        self.assertTrue('mime rule works' in headermatches, "mime rule failed")
        self.assertFalse('this should not match in a body rule' in headermatches,
                         'decoded body rule matched raw body')

        # perl style advanced rules
        self.assertTrue('perl-style /-notation works!' in headermatches,
                        "new rule format failed: %s" % headermatches)
        self.assertTrue('perl-style recipient match' in headermatches,
                        "new rule format failed for to_domain: %s" % headermatches)
        self.assertFalse('this should not match' in headermatches,
                         "rule flag ignorecase was not detected")

        # TODO: raw body rules

    def test_sf_matches(self):
        """Test SuspectFilter extended matches"""

        suspect = Suspect('sender@unittests.fuglu.org',
                          'recipient@unittests.fuglu.org', TESTDATADIR + '/helloworld.eml')

        (match, info) = self.candidate.matches(suspect, extended=True)
        self.assertTrue(match, 'Match should return True')
        field, matchedvalue, arg, regex = info
        self.assertTrue(field == 'to_domain')
        self.assertTrue(matchedvalue == 'unittests.fuglu.org')
        self.assertTrue(arg == 'Sent to unittest domain!')
        self.assertTrue(regex == 'unittests\.fuglu\.org')

    def test_sf_get_field(self):
        """Test SuspectFilter field extract"""
        suspect = Suspect('sender@unittests.fuglu.org',
                          'recipient@unittests.fuglu.org', TESTDATADIR + '/helloworld.eml')

        # additional field tests
        self.assertEqual(self.candidate.get_field(
            suspect, 'clienthelo')[0], 'helo1')
        self.assertEqual(self.candidate.get_field(
            suspect, 'clientip')[0], '10.0.0.1')
        self.assertEqual(self.candidate.get_field(
            suspect, 'clienthostname')[0], 'rdns1')

    def test_strip(self):
        html = """foo<a href="bar">bar</a><script language="JavaScript">echo('hello world');</script>baz"""

        declarationtest = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="de">
  <head>
    <title>greetings</title>
  </head>
  <body>
    <font color="red">well met!</font>
  </body>
</html>
"""
        # word generated empty message
        wordhtml = """<html xmlns:v=3D"urn:schemas-microsoft-com:vml"
xmlns:o=3D"urn:schemas-microsoft-com:office:office"
xmlns:w=3D"urn:schemas-microsoft-com:office:word"
xmlns:m=3D"http://schemas.microsoft.com/office/2004/12/omml"
xmlns=3D"http://www.w3.org/TR/REC-html40"><head><META
HTTP-EQUIV=3D"Content-Type" CONTENT=3D"text/html;
charset=3Dus-ascii"><meta name=3DGenerator content=3D"Microsoft Word 15
(filtered medium)"><style><!--
/* Font Definitions */
@font-face
	{font-family:"Cambria Math";
	panose-1:2 4 5 3 5 4 6 3 2 4;}
@font-face
	{font-family:Calibri;
	panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
	{margin:0cm;
	margin-bottom:.0001pt;
	font-size:11.0pt;
	font-family:"Calibri",sans-serif;
	mso-fareast-language:EN-US;}
a:link, span.MsoHyperlink
	{mso-style-priority:99;
	color:#0563C1;
	text-decoration:underline;}
a:visited, span.MsoHyperlinkFollowed
	{mso-style-priority:99;
	color:#954F72;
	text-decoration:underline;}
span.E-MailFormatvorlage17
	{mso-style-type:personal-compose;
	font-family:"Calibri",sans-serif;
	color:windowtext;}
.MsoChpDefault
	{mso-style-type:export-only;
	font-family:"Calibri",sans-serif;
	mso-fareast-language:EN-US;}
@page WordSection1
	{size:612.0pt 792.0pt;
	margin:70.85pt 70.85pt 2.0cm 70.85pt;}
div.WordSection1
	{page:WordSection1;}
--></style><!--[if gte mso 9]><xml>
<o:shapedefaults v:ext=3D"edit" spidmax=3D"1026" />
</xml><![endif]--><!--[if gte mso 9]><xml>
<o:shapelayout v:ext=3D"edit">
<o:idmap v:ext=3D"edit" data=3D"1" />
</o:shapelayout></xml><![endif]--></head><body lang=3DDE-CH
link=3D"#0563C1" vlink=3D"#954F72"><div class=3DWordSection1><p
class=3DMsoNormal><o:p> </o:p></p></div></body></html>"""

        for use_bfs in [True, False]:
            stripped = self.candidate.strip_text(html, use_bfs=use_bfs)
            self.assertEqual(stripped, 'foobarbaz')

            docstripped = self.candidate.strip_text(
                declarationtest, use_bfs=use_bfs)
            self.assertEqual(
                docstripped.split(), ['greetings', 'well', 'met!'])

            wordhtmstripped = self.candidate.strip_text(
                wordhtml, use_bfs=use_bfs)
            self.assertEqual(wordhtmstripped.strip(), '')


class ActionCodeTestCase(unittest.TestCase):

    def test_defaultcodes(self):
        """test actioncode<->string conversion"""
        conf = ConfigParser()
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
        self.assertEqual(
            result, expected), "Got unexpected template result: %s" % result


class ClientInfoTestCase(unittest.TestCase):

    """Test client info detection"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_parse_rcvd_header(self):
        suspect = Suspect('sender@unittests.fuglu.org',
                          'recipient@unittests.fuglu.org', '/dev/null')
        self.assertEqual(suspect._parse_rcvd_header(
            "from helo1 (rdns1 [10.0.0.1])"), ('helo1', 'rdns1', '10.0.0.1'))
        self.assertEqual(suspect._parse_rcvd_header("from mx0.slc.paypal.com (mx1.slc.paypal.com [173.0.84.226])"), (
            'mx0.slc.paypal.com', 'mx1.slc.paypal.com', '173.0.84.226'))
        self.assertEqual(suspect._parse_rcvd_header("from mail1a.tilaa.nl (mail1a.tilaa.nl [IPv6:2a02:2770:6:0:21a:4aff:fea8:1328])"), (
            'mail1a.tilaa.nl', 'mail1a.tilaa.nl', '2a02:2770:6:0:21a:4aff:fea8:1328'))

    def test_client_info(self):
        """Test client info using eml file"""
        suspect = Suspect('sender@unittests.fuglu.org',
                          'recipient@unittests.fuglu.org', TESTDATADIR + '/helloworld.eml')
        helo, ip, revdns = suspect.client_info_from_rcvd(None, 0)
        self.assertEqual(helo, 'helo1')
        self.assertEqual(ip, '10.0.0.1')
        self.assertEqual(revdns, 'rdns1')

        helo, ip, revdns = suspect.client_info_from_rcvd(None, 1)
        self.assertEqual(helo, 'helo2')
        self.assertEqual(ip, '10.0.0.2')
        self.assertEqual(revdns, 'rdns2')

        helo, ip, revdns = suspect.client_info_from_rcvd('10\.0\.0\.2', 1)
        self.assertEqual(helo, 'helo3')
        self.assertEqual(ip, '10.0.0.3')
        self.assertEqual(revdns, 'rdns3')


class FileListTestCase(unittest.TestCase):

    def setUp(self):
        testdata = """CASE?
{whitespace}stripped ?{whitespace}
{whitespace}

{whitespace}# no comment!
""".format(whitespace='    ')
        self.filename = '/tmp/fuglufilelisttest.txt'
        open(self.filename, 'w').write(testdata)

    def tearDown(self):
        os.unlink(self.filename)

    def test_filelist(self):
        self.assertEqual(FileList(filename=self.filename, strip=True, skip_empty=True, skip_comments=True,
                                  lowercase=False, additional_filters=None).get_list(), ['CASE?', 'stripped ?'])
        self.assertEqual(FileList(filename=self.filename, strip=False, skip_empty=True, skip_comments=True,
                                  lowercase=False, additional_filters=None).get_list(), ['CASE?', '    stripped ?    ', '    '])
        self.assertEqual(FileList(filename=self.filename, strip=True, skip_empty=False, skip_comments=False,
                                  lowercase=False, additional_filters=None).get_list(), ['CASE?', 'stripped ?', '', '', '# no comment!'])
        self.assertEqual(FileList(filename=self.filename, strip=True, skip_empty=True, skip_comments=True,
                                  lowercase=True, additional_filters=None).get_list(), ['case?', 'stripped ?'])
