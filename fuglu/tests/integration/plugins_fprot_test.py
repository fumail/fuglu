import integrationtestsetup
import unittest
from fuglu.plugins.fprot import FprotPlugin

import logging


class FprotTestCase(unittest.TestCase):

    def setUp(self):
        try:
            from configparser import RawConfigParser
        except ImportError:
            from ConfigParser import RawConfigParser
        config = RawConfigParser()
        config.add_section('FprotPlugin')
        config.set('FprotPlugin', 'host', 'localhost')
        config.set('FprotPlugin', 'port', '10200')
        config.set('FprotPlugin', 'timeout', '20')
        config.set('FprotPlugin', 'maxsize', '10485000')
        config.set('FprotPlugin', 'retries', '3')
        config.set('FprotPlugin', 'networkmode', '0')
        self.candidate = FprotPlugin(config)

    def test_eicar(self):
        """Test eicar detection"""
        try:
            self.candidate.__init_socket__()
        except:
            logging.warn("f-prot not reachable - not running test")
            return

        virlist = self.candidate.scan_file('testdata/eicar.eml')
        self.assertTrue(
            "EICAR_Test_File" in list(virlist.values()), "Eicar not found in scan_file")

        fp = open('testdata/eicar.eml', 'r')
        buffer = fp.read()
        fp.close()
        virlist = self.candidate.scan_stream(buffer)
        self.assertTrue(
            "EICAR_Test_File" in list(virlist.values()), "Eicar not found in scan_stream")
