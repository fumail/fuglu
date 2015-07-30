from fuglu.shared import Suspect, AppenderPlugin, actioncode_to_string
import platform
from socket import socket, AF_INET, SOCK_DGRAM


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
        if timings == None:
            return

        buffer = ""
        if self.sock == None:
            self.sock = socket(AF_INET, SOCK_DGRAM)

        for section, time in timings:
            buffer = "%s%s.fuglu.plugin.%s:%s|ms\n" % (
                buffer, self.nodename, section, int(time * 1000))
        addr = self.config.get(self.section, 'host'), self.config.getint(
            self.section, 'port')
        self.sock.sendto(buffer.encode('utf-8'), addr)

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
        buffer = "%s.fuglu.decision.%s:1|c\n" % (
            self.nodename, actioncode_to_string(decision))
        if self.sock == None:
            self.sock = socket(AF_INET, SOCK_DGRAM)

        if suspect.is_virus():
            buffer = "%s%s.fuglu.message.virus:1|c\n" % (buffer, self.nodename)
        elif suspect.is_highspam():
            buffer = "%s%s.fuglu.message.highspam:1|c\n" % (
                buffer, self.nodename)
        elif suspect.is_spam():
            buffer = "%s%s.fuglu.message.spam:1|c\n" % (buffer, self.nodename)
        else:
            buffer = "%s%s.fuglu.message.clean:1|c\n" % (buffer, self.nodename)

        addr = self.config.get(self.section, 'host'), self.config.getint(
            self.section, 'port')
        self.sock.sendto(buffer.encode('utf-8'), addr)

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
        recipient = suspect.to_domain
        if self.config.get(self.section, 'level') == 'email':
            recipient = suspect.to_address
        recipient = recipient.replace('.', '-')
        recipient = recipient.replace('@', '--')

        buffer = ""
        if self.sock == None:
            self.sock = socket(AF_INET, SOCK_DGRAM)

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

        addr = self.config.get(self.section, 'host'), self.config.getint(
            self.section, 'port')
        self.sock.sendto(buffer.encode('utf-8'), addr)
        #self.logger.info("buffer: %s"%buffer)

    def __str__(self):
        return 'Statsd Sender: Per Recipient Message Status'
