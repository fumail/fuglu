import os
import sys
import logging
import socket

UNITTESTDIR = os.path.dirname(os.path.realpath(__file__))
CODEDIR = os.path.abspath(UNITTESTDIR + '../../../src')
TESTDATADIR = os.path.abspath(UNITTESTDIR + '/testdata')
CONFDIR = os.path.abspath(CODEDIR + '/../conf')

sys.path.insert(0, CODEDIR)

from fuglu.connectors.smtpconnector import SMTPSession


def guess_clamav_socket(config):
    """depending on the test environment, clamav may be using a tcp port or running on a unix socket
    try to guess the correct setting
    """
    config.set('ClamavPlugin', 'port', '3310')
    # try local socket:
    knownpaths = [
        '/var/lib/clamav/clamd.sock',
        '/var/run/clamav/clamd.ctl',
    ]
    for p in knownpaths:
        if os.path.exists(p):
            config.set('ClamavPlugin', 'port', p)
            break


class DummySMTPServer(object):

    """one-time smtp server to test re-injects"""

    def __init__(self, config, port=11026, address="127.0.0.1"):
        self.logger = logging.getLogger("dummy.smtpserver")
        self.logger.debug('Starting dummy SMTP Server on Port %s' % port)
        self.port = port
        self.config = config
        self.tempfilename = None

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((address, port))
        self._socket.listen(1)
        self.suspect = None

    def serve(self):
        from fuglu.shared import Suspect
        nsd = self._socket.accept()

        sess = SMTPSession(nsd[0], self.config)
        success = sess.getincomingmail()
        if not success:
            self.logger.error('incoming smtp transfer did not finish')
            return
        sess.endsession(250, "OK - queued as 1337 ")

        fromaddr = sess.from_address

        toaddr = sess.to_address
        self.tempfilename = sess.tempfilename
        self.logger.debug("Message from %s to %s stored to %s" %
                          (fromaddr, toaddr, self.tempfilename))

        self.suspect = Suspect(fromaddr, toaddr, self.tempfilename)

    def shutdown(self):
        try:
            self._socket.shutdown(1)
            self._socket.close()
        except:
            pass
        self.logger.info('Dummy smtp server on port %s shut down' % self.port)
