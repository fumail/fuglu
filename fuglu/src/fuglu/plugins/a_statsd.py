from fuglu.shared import AppenderPlugin, actioncode_to_string
from fuglu.localStringEncoding import force_bString, force_uString
import platform
import socket


class PluginTime(AppenderPlugin):

    """EXPERIMENTAL: Send Plugin execution time to a statsd server"""

    def __init__(self, config, section=None):
        AppenderPlugin.__init__(self, config, section)
        self.logger = self._logger()

        self.requiredvars = {
            'host': {
                'default': '127.0.0.1',
                'description': 'statsd host',
            },

            'port': {
                'default': '8125',
                'description': 'statsd port',
            },
        }
        self.sock = None
        self.nodename = platform.node().split('.')[0]


    def process(self, suspect, decision):
        timings = suspect.get_tag('scantimes')
        if timings is None:
            return

        host = self.config.get(self.section, 'host')
        port = int(self.config.get(self.section, 'port'))

        buffer = ""
        if self.sock is None:
            addr_f = socket.getaddrinfo(host, 0)[0][0]
            self.sock = socket.socket(addr_f, socket.SOCK_DGRAM)

        for section, time in timings:
            buffer = "%s%s.fuglu.plugin.%s:%s|ms\n" % (
                buffer, self.nodename, section, int(time * 1000))
        self.sock.sendto(buffer.encode('utf-8'), (host, port))

    def __str__(self):
        return 'Statsd Sender: Plugin Time'


class MessageStatus(AppenderPlugin):

    """EXPERIMENTAL: Send message status to a statsd server"""

    def __init__(self, config, section=None):
        AppenderPlugin.__init__(self, config, section)
        self.logger = self._logger()

        self.requiredvars = {
            'host': {
                'default': '127.0.0.1',
                'description': 'statsd host',
            },

            'port': {
                'default': '8125',
                'description': 'statsd port',
            },
        }
        self.sock = None
        self.nodename = platform.node().split('.')[0]


    def process(self, suspect, decision):
        buffer = "%s.fuglu.decision.%s:1|c\n" % (self.nodename, actioncode_to_string(decision))

        host = self.config.get(self.section, 'host')
        port = int(self.config.get(self.section, 'port'))

        if self.sock is None:
            addr_f = socket.getaddrinfo(host, 0)[0][0]
            self.sock = socket.socket(addr_f, socket.SOCK_DGRAM)

        if suspect.is_virus():
            buffer = "%s%s.fuglu.message.virus:1|c\n" % (buffer, self.nodename)
        elif suspect.is_highspam():
            buffer = "%s%s.fuglu.message.highspam:1|c\n" % (
                buffer, self.nodename)
        elif suspect.is_spam():
            buffer = "%s%s.fuglu.message.spam:1|c\n" % (buffer, self.nodename)
        else:
            buffer = "%s%s.fuglu.message.clean:1|c\n" % (buffer, self.nodename)

        self.sock.sendto(force_bString(buffer), (host,port))

    def __str__(self):
        return 'Statsd Sender: Global Message Status'


class MessageStatusPerRecipient(AppenderPlugin):

    """EXPERIMENTAL: Send per recipient stats to a statsd server"""

    def __init__(self, config, section=None):
        AppenderPlugin.__init__(self, config, section)
        self.logger = self._logger()

        self.requiredvars = {
            'host': {
                'default': '127.0.0.1',
                'description': 'statsd host',
            },

            'port': {
                'default': '8125',
                'description': 'statsd port',
            },
            'level': {
                'default': 'domain',
                'description': 'domain: send stats per recipient domain. email: send stats per recipient email address'
            }
        }
        self.sock = None
        self.nodename = platform.node().split('.')[0]


    def process(self, suspect, decision):
        recipient = force_uString(suspect.to_domain) # work with unicode string
        if self.config.get(self.section, 'level') == 'email':
            recipient = suspect.to_address
        recipient = recipient.replace('.', '-')
        recipient = recipient.replace('@', '--')

        host = self.config.get(self.section, 'host')
        port = int(self.config.get(self.section, 'port'))

        buffer = ""
        if self.sock is None:
            addr_f = socket.getaddrinfo(host, 0)[0][0]
            self.sock = socket.socket(addr_f, socket.SOCK_DGRAM)

        if suspect.is_virus():
            buffer = "%s%s.fuglu.recipient.%s.virus:1|c\n" % (
                buffer, self.nodename, recipient)
        elif suspect.is_highspam():
            buffer = "%s%s.fuglu.recipient.%s.highspam:1|c\n" % (
                buffer, self.nodename, recipient)
        elif suspect.is_spam():
            buffer = "%s%s.fuglu.recipient.%s.spam:1|c\n" % (
                buffer, self.nodename, recipient)
        else:
            buffer = "%s%s.fuglu.recipient.%s.clean:1|c\n" % (
                buffer, self.nodename, recipient)

        self.sock.sendto(force_bString(buffer), (host, port))
        #self.logger.info("buffer: %s"%buffer)


    def __str__(self):
        return 'Statsd Sender: Per Recipient Message Status'

