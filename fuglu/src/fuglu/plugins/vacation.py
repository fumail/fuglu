# -*- coding: utf-8 -*-
#   Copyright 2009-2016 Oli Schacher
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
#
"""
Vacation/Autoreply Plugin
"""

from fuglu.shared import ScannerPlugin, DUNNO
from fuglu.bounce import Bounce
import fuglu.extensions.sql
import time
import re
from threading import Lock
from datetime import datetime, timedelta
import logging
import traceback
from email.mime.text import MIMEText
from email.header import Header

# from address regex
vacation_ignoresenderregex = ["^owner-",
                              "^request-",
                              "-request@",
                              # everything with 'bounce' in the lefthandside is
                              # probably automated
                              "bounce.*@",
                              "-confirm@",
                              "-errors@",
                              "^no[\-]?reply",
                              "^donotreply",
                              "^postmaster@",
                              "^mailer[-_]daemon@",
                              "^mailer@",
                              "^listserv@",
                              "^majordom[o]?@",
                              "^mailman@",
                              "^nobody@",
                              "^bounce",
                              "^www(-data)?@",
                              "^mdaemon@",
                              "^root@",
                              "^webmaster@",
                              "^administrator@",
                              "^support@",
                              "^news(letter)?@",
                              ]


# if one of these headers exists, we should not send auto reply
vacation_ignoreheaderexists = ["list-help",
                               "list-unsubscribe",
                               "list-subscribe",
                               "list-owner",
                               "list-post",
                               "list-archive",
                               "list-id",
                               "mailing-List",
                               "x-facebook-notify",
                               "x-mailing-list",
                               'x-cron-env',
                               'x-autoresponse',
                               'x-eBay-mailtracker'
                               ]
# if these headers exist and match regex, we should not send auto reply
vacation_ignoreheaderregex = {
    'x-spam-flag': 'yes',
    'x-spam-status': 'yes',
    'X-Spam-Flag2': 'yes',
    'X-Bluewin-Spam-Score': '^100',
    'precedence': '(bulk|list|junk)',
    'x-precedence': '(bulk|list|junk)',
    'x-barracuda-spam-status': 'yes',
    'x-dspam-result': '(spam|bl[ao]cklisted)',
    'X-Mailer': '^Mail$',
    'auto-submitted': 'auto-replied',
    'X-Auto-Response-Suppress': '(AutoReply|OOF)',
}


class Vacation(object):

    """represents a user defined vacation"""

    def __init__(self):
        self.enabled = True
        self.created = None
        self.start = None
        self.end = None
        self.awayuser = None
        self.subject = None
        self.body = None
        self.ignoresender = None

    def __str__(self):
        return "Vacation(%s) start=%s end=%s ignore=%s" % (self.awayuser, self.start, self.end, self.ignoresender)

    def __repr__(self):
        return str(self)


class VacationReply(object):

    """a reply to a vacation message for logging to the database"""

    def __init__(self):
        self.sent = None
        self.recipient = None


if fuglu.extensions.sql.ENABLED:
    from sqlalchemy import Table, Column, TEXT, TIMESTAMP, Integer, String, MetaData, ForeignKey, Unicode, Boolean, DateTime, select
    from sqlalchemy.sql import and_
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import mapper, relation, column_property, object_session
    DeclarativeBase = declarative_base()
    metadata = DeclarativeBase.metadata

    vacation_table = Table("vacation", metadata,
                           Column('id', Integer, primary_key=True),
                           Column('created', TIMESTAMP, nullable=False),
                           Column(
                               'enabled', Boolean, nullable=False, default=True),
                           Column('start', TIMESTAMP, nullable=False),
                           Column('end', TIMESTAMP, nullable=False),
                           Column(
                               'awayuser', Unicode(255), unique=True, nullable=False),
                           Column('subject', Unicode(255), nullable=False),
                           Column('body', TEXT, nullable=False),
                           Column('ignoresender', TEXT, nullable=False),
                           )

    vacationreply_table = Table("vacationreply", metadata,
                                Column('id', Integer, primary_key=True),
                                Column(
                                    'vacation_id', None, ForeignKey('vacation.id')),
                                Column('sent', TIMESTAMP, nullable=False),
                                Column(
                                    'recipient', Unicode(255), nullable=False),
                                )
    vacation_mapper = mapper(Vacation, vacation_table)

    vacationreply_mapper = mapper(VacationReply, vacationreply_table,
                                  properties=dict(
                                      vacation=relation(
                                          Vacation, backref='replies'),
                                  )
                                  )


class VacationCache(object):

    """caches vacation and compiled regex patterns"""

    __shared_state = {}

    def __init__(self, config):
        self.__dict__ = self.__shared_state
        if not hasattr(self, 'vacations'):
            self.vacations = {}
        if not hasattr(self, 'lock'):
            self.lock = Lock()
        if not hasattr(self, 'logger'):
            self.logger = logging.getLogger('fuglu.plugin.vacation.Cache')
        if not hasattr(self, 'lastreload'):
            self.lastreload = 0
        self.config = config
        self.reloadifnecessary()

    def reloadifnecessary(self):
        """reload vacation if older than 60 seconds"""
        if not time.time() - self.lastreload > 60:
            return
        if not self.lock.acquire():
            return
        try:
            self._loadvacation()
        finally:
            self.lock.release()

    def _loadvacation(self):
        """loads all vacations from database, do not call directly, only through reloadifnecessary"""
        self.logger.debug('Reloading vacation...')

        self.lastreload = time.time()

        newvacations = {}
        dbsession = fuglu.extensions.sql.get_session(
            self.config.get('VacationPlugin', 'dbconnectstring'), expire_on_commit=False)
        vaccounter = 0
        now = datetime.now()
        for vac in dbsession.query(Vacation).filter_by(enabled=True).filter(Vacation.start < now).filter(Vacation.end > now):
            vaccounter += 1
            self.logger.debug(vac)
            newvacations[vac.awayuser] = vac
        # important to expunge or other sessions wont be able to use this
        # vacation object
        dbsession.expunge_all()
        self.vacations = newvacations
        self.logger.debug('%s vacations loaded' % vaccounter)


class VacationPlugin(ScannerPlugin):

    """Sends out-of-office reply messages. Configuration is trough a sql database. Replies are only sent once per day per sender. The plugin will not reply to any 'automated' messages (Mailingslists, Spams, Bounces etc)

Requires: SQLAlechemy Extension


Required DB Tables: 
 * vacation (fuglu reads this table only, must be filled from elsewhere)

   * id int : id of this vacation
   * created timestamp :  creation timestamp
   * enabled boolean (eg. tinyint) : if disabled, no vacation reply will be sent
   * start timestamp: replies will only be sent after this point in time
   * end timestamp: replies will only be sent before this point in time
   * awayuser varchar: the email address of the user that is on vacation
   * subject: subject of the vacation message
   * body : body of the vacation message
   * ignoresender: whitespace delimited list of domains or email addresses that should not receive vacation replies

 * vacationreply (this table is filled by fuglu)

   * id int: id of the reply
   * vacation_id : id of the vacation
   * sent timestamp: timestamp when the reply was sent
   * recipient: recipient to whom the reply was sent

SQL Example for mysql:

::

    CREATE TABLE `vacation` (
      `id` int(11) NOT NULL auto_increment,
      `created` timestamp NOT NULL default now(),
      `start` timestamp NOT NULL,
      `end` timestamp NOT NULL ,
      `enabled` tinyint(1) NOT NULL default 1,
      `awayuser` varchar(255) NOT NULL,
      `subject` varchar(255) NOT NULL,
      `body` text NOT NULL,
      `ignoresender` text NOT NULL,
      PRIMARY KEY  (`id`),
      UNIQUE(`awayuser`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 ;


    CREATE  TABLE `vacationreply` (
      `id` int(11) NOT NULL auto_increment,
      `recipient` varchar(255) NOT NULL,
      `vacation_id` int(11) NOT NULL,
         `sent` timestamp not null default now(),
      PRIMARY KEY  (`id`),
      KEY `vacation_id` (`vacation_id`),
      CONSTRAINT `vacation_ibfk_1` FOREIGN KEY (`vacation_id`) REFERENCES `vacation` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;


"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {
            'dbconnectstring': {
                'default': '',
                'description': 'sqlalchemy connectstring to load vacations',
                'confidential': True,
            },
        }

        self.logger = self._logger()
        self.cache = None

    def __str__(self):
        return "Vacation"

    def _cache(self):
        if self.cache == None:
            self.cache = VacationCache(self.config)
        return self.cache

    def examine(self, suspect):
        # this plugin should not cause fuglu to defer
        try:
            vac = self.should_send_vacation_message(suspect)
            if vac != None:
                self.logger.debug('Vacation message candidate detected: Sender: %s recipient(on vacation): %s' % (
                    suspect.from_address, suspect.to_address))
                self.send_vacation_reply(suspect, vac)
        except Exception as e:
            exc = traceback.format_exc()
            self.logger.error("Exception in Vacation Plugin: %s" % e)
            self.logger.error(exc)
        return DUNNO

    def should_send_vacation_message(self, suspect):
        """do all necessary checks and return the vacation object if we should send a vacation message"""
        if suspect.is_spam() or suspect.is_virus():
            self.logger.debug(
                'Message already detected as spam or virus, not checking for vacation')
            return None

        self._cache().reloadifnecessary()

        vacation = self.on_vacation(suspect)
        if vacation == None:
            return None

        self.logger.debug(
            'Recipient is on vacation, performing additional checks')
        if self.ignore_sender(vacation, suspect):
            self.logger.debug(
                'Sender is on user ignore list: %s' % suspect.from_address)
            return None

        if self.non_human_sender(suspect):
            self.logger.debug(
                'Message appears to be from automated source - not sending vacation reply')
            return None

        if self.already_notified(vacation, suspect.from_address):
            self.logger.debug(
                'Sender %s already notified, not sending another vacation reply' % suspect.from_address)
            return None

        return vacation

    def on_vacation(self, suspect):
        """return Vacation object if recipient is on vacation, None otherwise"""
        toaddress = suspect.to_address
        todomain = suspect.to_domain

        allvacs = self._cache().vacations

        # check for individual vacation
        if toaddress in allvacs:
            return allvacs[toaddress]

        # domain wide vacation
        if todomain in allvacs:
            return allvacs[todomain]

        return None

    def ignore_sender(self, vacation, suspect):
        """return true if sender address/domain is on users ignore list"""
        senderignos = vacation.ignoresender.split()
        if suspect.from_address in senderignos or suspect.from_domain in senderignos:
            return True
        return False

    def non_human_sender(self, suspect):
        """returns True if this sender is non-human, eg. mailinglist, spam, bounce etc"""
        sender = suspect.from_address.lower()

        if sender == "" or sender == "<>":
            self.logger.debug('This is a bounce')
            return True

        for ignoregex in vacation_ignoresenderregex:
            if re.search(ignoregex, suspect.from_address, re.I):
                self.logger.debug('Blacklisted sender: %s' % sender)
                return True

        messagerep = suspect.get_message_rep()
        for ignoheader in vacation_ignoreheaderexists:
            if ignoheader in messagerep:
                self.logger.debug('Blacklisted header: %s' % ignoheader)
                return True

        for header, restring in list(vacation_ignoreheaderregex.items()):
            #self.logger.info("searching for header %s"%header)
            vals = messagerep.get_all(header)
            if vals != None:
                for val in vals:
                    if re.search(restring, val, re.I):
                        self.logger.debug(
                            'Blacklisted header value: %s: %s' % (header, val))
                        return True

        return False

    def already_notified(self, vacation, recipient):
        """return true if this user has been notfied in the last 24 hours"""
        dbsession = fuglu.extensions.sql.get_session(
            self.config.get(self.section, 'dbconnectstring'))
        log = dbsession.query(VacationReply).filter_by(vacation=vacation).filter(
            VacationReply.sent > datetime.now() - timedelta(days=1)).filter_by(recipient=recipient).first()
        dbsession.expunge_all()
        if log != None:
            self.logger.debug(
                'Sender %s already notfied at %s' % (log.recipient, log.sent))
            return True
        return False

    def send_vacation_reply(self, suspect, vacation):
        """send the vacation reply"""
        # http://mg.pov.lt/blog/unicode-emails-in-python

        bounce = Bounce(self.config)
        self.logger.debug('generating vacation message from %s to %s' % (
            suspect.to_address, suspect.from_address))

        # check subject
        subj = vacation.subject
        if subj == None or subj.strip() == '':
            self.logger.errror('Vacation has no subject, not sending message')
            return None

        # We must choose the body charset manually
        body = vacation.body
        if body == None:
            body = ''

        for body_charset in 'US-ASCII', 'ISO-8859-1', 'UTF-8':
            try:
                body.encode(body_charset)
            except UnicodeError:
                pass
            else:
                break

        msg = MIMEText(body.encode(body_charset), 'plain', body_charset)

        h = Header(vacation.subject, 'ISO-8859-1')
        msg['Subject'] = h
        msg['Precedence'] = 'bulk'
        msg['Auto-Submitted'] = 'auto-replied'
        msg['From'] = suspect.to_address
        msg['To'] = suspect.from_address

        msgcontent = msg.as_string()
        bounce.send_template_string(
            suspect.from_address, msgcontent, suspect, dict())
        self.log_bounce(suspect, vacation)
        return msgcontent

    def log_bounce(self, suspect, vacation):
        """log a bounce so we know tho whom we already sent"""
        log = VacationReply()
        log.recipient = suspect.from_address
        log.sent = datetime.now()
        log.vacation = vacation

        dbsession = fuglu.extensions.sql.get_session(
            self.config.get(self.section, 'dbconnectstring'))
        dbsession.add(log)
        dbsession.flush()
        dbsession.expunge_all()

    def lint(self):
        allok = (self.checkConfig() and self.lint_sql())
        return allok

    def lint_sql(self):
        if not fuglu.extensions.sql.ENABLED:
            print("Vacation requires the fuglu sql extension to be enabled")
            return False

        try:
            dbsession = fuglu.extensions.sql.get_session(
                self.config.get(self.section, 'dbconnectstring'))
            bind = dbsession.get_bind(Vacation)
            bind.connect()
            now = datetime.now()
            allvacs = dbsession.query(Vacation).filter_by(enabled=True).filter(
                Vacation.start < now).filter(Vacation.end > now)
            for vac in allvacs:
                print(vac)
        except Exception as e:
            print("Database error: %s" % str(e))
            return False

        return True
