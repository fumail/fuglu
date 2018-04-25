# -*- coding: UTF-8 -*-
from fuglu.shared import AVScannerPlugin, DUNNO, DEFER, string_to_actioncode, apply_template
import socket
import struct
import re
# from : https://github.com/AlexeyDemidov/avsmtpd/blob/master/drweb.h
# Dr. Web daemon commands
DRWEBD_SCAN_CMD = 0x0001
DRWEBD_VERSION_CMD = 0x0002
DRWEBD_BASEINFO_CMD = 0x0003
DRWEBD_IDSTRING_CMD = 0x0004
# DRWEBD_SCAN_FILE command flags: */
DRWEBD_RETURN_VIRUSES = 0x0001
DRWEBD_RETURN_REPORT = 0x0002
DRWEBD_RETURN_CODES = 0x0004
DRWEBD_HEURISTIC_ON = 0x0008
DRWEBD_SPAM_FILTER = 0x0020
# DrWeb result codes */
DERR_READ_ERR = 0x00001
DERR_WRITE_ERR = 0x00002
DERR_NOMEMORY = 0x00004
DERR_CRC_ERROR = 0x00008
DERR_READSOCKET = 0x00010
DERR_KNOWN_VIRUS = 0x00020
DERR_UNKNOWN_VIRUS = 0x00040
DERR_VIRUS_MODIFICATION = 0x00080
DERR_TIMEOUT = 0x00200
DERR_SYMLINK = 0x00400
DERR_NO_REGFILE = 0x00800
DERR_SKIPPED = 0x01000
DERR_TOO_BIG = 0x02000
DERR_TOO_COMPRESSED = 0x04000
DERR_BAD_CAL = 0x08000
DERR_EVAL_VERSION = 0x10000
DERR_SPAM_MESSAGE = 0x20000
DERR_VIRUS = DERR_KNOWN_VIRUS | DERR_UNKNOWN_VIRUS | DERR_VIRUS_MODIFICATION


class DrWebPlugin(AVScannerPlugin):

    """ This plugin passes suspects to a DrWeb scan daemon

EXPERIMENTAL Plugin: has not been tested in production.

Prerequisites: Dr.Web unix version must be installed and running, not necessarily on the same box as fuglu though.

Notes for developers:

Tags:

 * sets ``virus['drweb']`` (boolean)
 * sets ``DrWebPlugin.virus`` (list of strings) - virus names found in message
"""

    def __init__(self, config, section=None):
        AVScannerPlugin.__init__(self, config, section)

        self.requiredvars = {
            'host': {
                'default': 'localhost',
                'description': 'hostname where fpscand runs',
            },
            'port': {
                'default': '3000',
                'description': "DrWeb daemon port",
            },
            'timeout': {
                'default': '30',
                'description': "network timeout",
            },
            'maxsize': {
                'default': '22000000',
                'description': "maximum message size to scan",
            },
            'retries': {
                'default': '3',
                'description': "maximum retries on failed connections",
            },
            'virusaction': {
                'default': 'DEFAULTVIRUSACTION',
                'description': "plugin action if threat is detected",
            },
            'problemaction': {
                'default': 'DEFER',
                'description': "plugin action if scan fails",
            },

            'rejectmessage': {
                'default': 'threat detected: ${virusname}',
                'description': "reject message template if running in pre-queue mode and virusaction=REJECT",
            },
        }
        self.logger = self._logger()
        self.pattern = re.compile(r'(?:DATA\[\d+\])(.+) infected with (.+)$')
        self.enginename = 'drweb'
        

    def examine(self, suspect):
        if self._check_too_big(suspect):
            return DUNNO

        content = suspect.get_message_rep().as_string()

        for i in range(0, self.config.getint(self.section, 'retries')):
            try:
                viruses = self.scan_stream(content)
                actioncode, message = self._virusreport(suspect, viruses)
                return actioncode, message
            except Exception as e:
                self.logger.warning("Error encountered while contacting drweb (try %s of %s): %s" %
                                    (i + 1, self.config.getint(self.section, 'retries'), str(e)))
        self.logger.error("drweb scan failed after %s retries" %
                          self.config.getint(self.section, 'retries'))
        
        return self._problemcode()
    
    
    def _parse_result(self, lines):
        dr = {}
        for line in lines:
            line = line.strip()
            m = self.pattern.search(line)
            if m is None:
                continue
            filename = m.group(1)
            virus = m.group(2)
            dr[filename] = virus

        if len(dr) == 0:
            self.logger.warn(
                "could not extract virus information from report: %s" % "\n".join(lines))
            return dict(buffer='infection details unavailable')
        else:
            return dr
    
    
    def scan_stream(self, content, suspectid='(NA)'):
        """
        Scan a buffer

        content (string) : buffer to scan

        return either :
          - (dict) : {filename: "virusname"}
          - None if no virus found
        """

        s = self.__init_socket__()
        buflen = len(content)

        self._sendint(s, DRWEBD_SCAN_CMD)

        # flags:
        # self._sendint(s, 0) # "flags" # use this to get only the code
        # self._sendint(s, DRWEBD_RETURN_VIRUSES) # use this to get the virus
        # infection name
        # use this to get the full report
        self._sendint(s, DRWEBD_RETURN_REPORT)
        self._sendint(s, 0)  # not sure what this is for - but it's required.
        self._sendint(s, buflen)  # send the buffer length
        s.sendall(content)  # send the buffer
        retcode = self._readint(s)  # get return code
        # print "result=%s"%retcode
        numlines = self._readint(s)
        lines = []
        for _ in range(numlines):
            line = self._readstr(s)
            lines.append(line)
        s.close()

        if retcode & DERR_VIRUS == retcode:
            return self._parse_result(lines)
        else:
            return None
    
    
    def __init_socket__(self):
        host = self.config.get(self.section, 'host')
        port = self.config.getint(self.section, 'port')
        timeout = self.config.getint(self.section, 'timeout')
        try:
            s = socket.create_connection((host, port), timeout)
        except socket.error:
            raise Exception('Could not reach drweb using network (%s, %s)' % (host, port))

        return s
    
    
    def __str__(self):
        return 'DrWeb AV'
    
    
    def lint(self):
        allok = self.check_config() and self.lint_info() and self.lint_eicar()
        return allok
    
    
    def lint_info(self):
        try:
            version = self.get_version()
            bases = self.get_baseinfo()
            print("DrWeb Version %s, found %s bases with a total of %s virus definitions" % (
                version, len(bases), sum([x[1] for x in bases])))
        except Exception as e:
            print("Could not get DrWeb Version info: %s" % str(e))
            return False
        return True
    

    def get_version(self):
        """Return numeric version of the DrWeb daemon"""
        try:
            s = self.__init_socket__()
            self._sendint(s, DRWEBD_VERSION_CMD)
            version = self._readint(s)
            return version
        except Exception as e:
            self.logger.error("Could not get DrWeb Version: %s" % str(e))
        return None
    
    
    def get_baseinfo(self):
        """return list of tuples (basename,number of virus definitions)"""
        ret = []
        try:
            s = self.__init_socket__()
            self._sendint(s, DRWEBD_BASEINFO_CMD)
            numbases = self._readint(s)
            for _ in range(numbases):
                idstr = self._readstr(s)
                numviruses = self._readint(s)
                ret.append((idstr, numviruses))
        except Exception as e:
            self.logger.error(
                "Could not get DrWeb Base Information: %s" % str(e))
            return None
        return ret
    
    
    def _sendint(self, sock, value):
        sock.sendall(struct.pack('!I', value))
    
    
    def _readint(self, sock):
        res = sock.recv(4)
        ret = struct.unpack('!I', res)[0]
        return ret
    
    
    def _readstr(self, sock):
        strlength = self._readint(sock)
        buf = sock.recv(strlength)
        if buf[-1] == '\0':  # chomp null terminated string
            buf = buf[:-1]
        return buf


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    try:
        from configparser import RawConfigParser
    except ImportError:
        from ConfigParser import RawConfigParser
    config = RawConfigParser()
    sec = 'dev'
    config.add_section(sec)
    config.set(sec, 'host', 'localhost')
    config.set(sec, 'port', '3000')
    config.set(sec, 'timeout', '5')
    plugin = DrWebPlugin(config, sec)

    assert plugin.lint_info()

    import sys
    if len(sys.argv) > 1:
        counter = 0
        infected = 0
        for file in sys.argv[1:]:
            counter += 1
            with open(file, 'rb') as fp:
                buf = fp.read()
            res = plugin.scan_stream(buf)
            if res is None:
                print("%s: clean" % file)
            else:
                infected += 1
                print("%s: infection(s) found: " % file)
                for fname, infection in res.items():
                    print("- %s is infected with %s" % (fname, infection))
        print("")
        print("%s / %s files infected" % (infected, counter))
    else:
        plugin.lint_eicar()

