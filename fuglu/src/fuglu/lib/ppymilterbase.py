# $Id: ppymilterbase.py 33 2009-04-08 20:40:02Z codewhale $
# ==============================================================================
# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================
#
# Pure python milter interface (does not use libmilter.a).
# Handles parsing of milter protocol data (e.g. over a network socket)
# and provides standard arguments to the callbacks in your handler class.
#
# For details of the milter protocol see:
#  http://search.cpan.org/src/AVAR/Sendmail-PMilter-0.96/doc/milter-protocol.txt
#

__author__ = 'Eric DeFriez'

import binascii
import logging
import os
import socket
import struct
import sys
import types


MILTER_VERSION = 2  # Milter version we claim to speak (from pmilter)

# Potential milter command codes and their corresponding PpyMilter callbacks.
# From sendmail's include/libmilter/mfdef.h
SMFIC_ABORT = 'A'  # "Abort"
SMFIC_BODY = 'B'  # "Body chunk"
SMFIC_CONNECT = 'C'  # "Connection information"
SMFIC_MACRO = 'D'  # "Define macro"
SMFIC_BODYEOB = 'E'  # "final body chunk (End)"
SMFIC_HELO = 'H'  # "HELO/EHLO"
SMFIC_HEADER = 'L'  # "Header"
SMFIC_MAIL = 'M'  # "MAIL from"
SMFIC_EOH = 'N'  # "EOH"
SMFIC_OPTNEG = 'O'  # "Option negotation"
SMFIC_RCPT = 'R'  # "RCPT to"
SMFIC_QUIT = 'Q'  # "QUIT"
SMFIC_DATA = 'T'  # "DATA"
SMFIC_UNKNOWN = 'U'  # "Any unknown command"

COMMANDS = {
    SMFIC_ABORT: 'Abort',
    SMFIC_BODY: 'Body',
    SMFIC_CONNECT: 'Connect',
    SMFIC_MACRO: 'Macro',
    SMFIC_BODYEOB: 'EndBody',
    SMFIC_HELO: 'Helo',
    SMFIC_HEADER: 'Header',
    SMFIC_MAIL: 'MailFrom',
    SMFIC_EOH: 'EndHeaders',
    SMFIC_OPTNEG: 'OptNeg',
    SMFIC_RCPT: 'RcptTo',
    SMFIC_QUIT: 'Quit',
    SMFIC_DATA: 'Data',
    SMFIC_UNKNOWN: 'Unknown',
}

# To register/mask callbacks during milter protocol negotiation with sendmail.
# From sendmail's include/libmilter/mfdef.h
NO_CALLBACKS = 127  # (all seven callback flags set: 1111111)
CALLBACKS = {
    'OnConnect':    1,  # 0x01 SMFIP_NOCONNECT # Skip SMFIC_CONNECT
    'OnHelo':       2,  # 0x02 SMFIP_NOHELO    # Skip SMFIC_HELO
    'OnMailFrom':   4,  # 0x04 SMFIP_NOMAIL    # Skip SMFIC_MAIL
    'OnRcptTo':     8,  # 0x08 SMFIP_NORCPT    # Skip SMFIC_RCPT
    'OnBody':       16,  # 0x10 SMFIP_NOBODY    # Skip SMFIC_BODY
    'OnHeader':     32,  # 0x20 SMFIP_NOHDRS    # Skip SMFIC_HEADER
    'OnEndHeaders': 64,  # 0x40 SMFIP_NOEOH     # Skip SMFIC_EOH
}

# Acceptable response commands/codes to return to sendmail (with accompanying
# command data).  From sendmail's include/libmilter/mfdef.h
RESPONSE = {
    'ADDRCPT': '+',  # SMFIR_ADDRCPT    # "add recipient"
    'DELRCPT': '-',  # SMFIR_DELRCPT    # "remove recipient"
    'ACCEPT': 'a',  # SMFIR_ACCEPT     # "accept"
    'REPLBODY': 'b',  # SMFIR_REPLBODY   # "replace body (chunk)"
    'CONTINUE': 'c',  # SMFIR_CONTINUE   # "continue"
    'DISCARD': 'd',  # SMFIR_DISCARD    # "discard"
    'CONNFAIL': 'f',  # SMFIR_CONN_FAIL  # "cause a connection failure"
    'ADDHEADER': 'h',  # SMFIR_ADDHEADER  # "add header"
    'INSHEADER': 'i',  # SMFIR_INSHEADER  # "insert header"
    'CHGHEADER': 'm',  # SMFIR_CHGHEADER  # "change header"
    'PROGRESS': 'p',  # SMFIR_PROGRESS   # "progress"
    'QUARANTINE': 'q',  # SMFIR_QUARANTINE # "quarantine"
    'REJECT': 'r',  # SMFIR_REJECT     # "reject"
    'SETSENDER': 's',  # v3 only?
    'TEMPFAIL': 't',  # SMFIR_TEMPFAIL   # "tempfail"
    'REPLYCODE': 'y',  # SMFIR_REPLYCODE  # "reply code etc"
}


def printchar(char):
    """Useful debugging function for milter developers."""
    print('char: %s [qp=%s][hex=%s][base64=%s]' %
          (char, binascii.b2a_qp(char), binascii.b2a_hex(char),
           binascii.b2a_base64(char)))


def CanonicalizeAddress(addr):
    """Strip angle brackes from email address iff not an empty address ("<>").

    Args:
      addr: the email address to canonicalize (strip angle brackets from).

    Returns:
      The addr with leading and trailing angle brackets removed unless
      the address is "<>" (in which case the string is returned unchanged).
    """
    if addr == '<>':
        return addr
    return addr.lstrip('<').rstrip('>')


class PpyMilterException(Exception):

    """Parent of all other PpyMilter exceptions.  Subclass this: do not
    construct or catch explicitly!"""


class PpyMilterPermFailure(PpyMilterException):

    """Milter exception that indicates a perment failure."""


class PpyMilterTempFailure(PpyMilterException):

    """Milter exception that indicates a temporary/transient failure."""


class PpyMilterCloseConnection(PpyMilterException):

    """Exception that indicates the server should close the milter connection."""


class PpyMilterActionError(PpyMilterException):

    """Exception raised when an action is performed that was not negotiated."""


class PpyMilterDispatcher(object):

    """Dispatcher class for a milter server.  This class accepts entire
    milter commands as a string (command character + binary data), parses
    the command and binary data appropriately and invokes the appropriate
    callback function in a milter_class instance.  One PpyMilterDispatcher
    per socket connection.  One milter_class instance per PpyMilterDispatcher
    (per socket connection)."""

    def __init__(self, milter):
        """Construct a PpyMilterDispatcher and create a private
        milter_class instance.

        Args:
          milter_class: A class (not an instance) that handles callbacks for
                        milter commands (e.g. a child of the PpyMilter class).
        """
        self.__milter = milter

    def Dispatch(self, data):
        """Callback function for the milter socket server to handle a single
        milter command.  Parses the milter command data, invokes the milter
        handler, and formats a suitable response for the server to send
        on the socket.

        Args:
          data: A (binary) string (consisting of a command code character
                followed by binary data for that command code).

        Returns:
          A binary string to write on the socket and return to sendmail.  The
          string typically consists of a RESPONSE[] command character then
          some response-specific protocol data.

        Raises:
          PpyMilterCloseConnection: Indicating the (milter) connection should
                                    be closed.
        """
        (cmd, data) = (data[0], data[1:])
        try:
            if cmd not in COMMANDS:
                logging.warn('Unknown command code: "%s" ("%s")', cmd, data)
                return RESPONSE['CONTINUE']
            command = COMMANDS[cmd]
            parser_callback_name = '_Parse%s' % command
            handler_callback_name = 'On%s' % command

            if not hasattr(self, parser_callback_name):
                logging.error('No parser implemented for "%s"', command)
                return RESPONSE['CONTINUE']

            if not hasattr(self.__milter, handler_callback_name):
                logging.warn('Unimplemented command in milter %s: "%s" ("%s")' % (
                    self.__milter, command, data))
                return RESPONSE['CONTINUE']

            parser = getattr(self, parser_callback_name)
            callback = getattr(self.__milter, handler_callback_name)
            args = parser(cmd, data)
            return callback(*args)
        except PpyMilterTempFailure as e:
            logging.info('Temp Failure: %s', str(e))
            return RESPONSE['TEMPFAIL']
        except PpyMilterPermFailure as e:
            logging.info('Perm Failure: %s', str(e))
            return RESPONSE['REJECT']
        return RESPONSE['CONTINUE']

    def _ParseOptNeg(self, cmd, data):
        """Parse the 'OptNeg' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple consisting of:
            cmd: The single character command code representing this command.
            ver: The protocol version we support.
            actions: Bitmask of the milter actions we may perform
                     (see "PpyMilter.ACTION_*").
            protocol: Bitmask of the callback functions we are registering.

        """
        (ver, actions, protocol) = struct.unpack('!III', data)
        return (cmd, ver, actions, protocol)

    def _ParseMacro(self, cmd, data):
        """Parse the 'Macro' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple consisting of:
            cmd: The single character command code representing this command.
            macro: The single character command code this macro is for.
            data: A list of strings alternating between name, value of macro.
        """
        (macro, data) = (data[0], data[1:])
        return (cmd, macro, data.split('\0'))

    def _ParseConnect(self, cmd, data):
        """Parse the 'Connect' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple (cmd, hostname, family, port, address) where:
            cmd: The single character command code representing this command.
            hostname: The hostname that originated the connection to the MTA.
            family: Address family for connection (see sendmail libmilter/mfdef.h).
            port: The network port if appropriate for the connection.
            address: Remote address of the connection (e.g. IP address).
        """
        (hostname, data) = data.split('\0', 1)
        family = struct.unpack('c', data[0])[0]
        if family in ('4', '6'):  # SMFIA_INET / SMFIA_INET6
            port = struct.unpack('!H', data[1:3])[0]
            address, _ = data[3:].split('\0', 1)
        else:  # SMFIA_UNKNOWN / SMFIA_UNIX
            port = None
            address = None
        return (cmd, hostname, family, port, address)

    def _ParseHelo(self, cmd, data):
        """Parse the 'Helo' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple (cmd, data) where:
            cmd: The single character command code representing this command.
            data: TODO: parse this better
        """
        data = data.split('\0')[0]

        return (cmd, data)

    def _ParseMailFrom(self, cmd, data):
        """Parse the 'MailFrom' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple (cmd, mailfrom, esmtp_info) where:
            cmd: The single character command code representing this command.
            mailfrom: The canonicalized MAIL From email address.
            esmtp_info: Extended SMTP (esmtp) info as a list of strings.
        """
        (mailfrom, esmtp_info) = data.split('\0', 1)
        return (cmd, CanonicalizeAddress(mailfrom), esmtp_info.split('\0'))

    def _ParseRcptTo(self, cmd, data):
        """Parse the 'RcptTo' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple (cmd, rcptto, emstp_info) where:
            cmd: The single character command code representing this command.
            rcptto: The canonicalized RCPT To email address.
            esmtp_info: Extended SMTP (esmtp) info as a list of strings.
        """
        (rcptto, esmtp_info) = data.split('\0', 1)
        return (cmd, CanonicalizeAddress(rcptto), esmtp_info.split('\0'))

    def _ParseHeader(self, cmd, data):
        """Parse the 'Header' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple (cmd, key, val) where:
            cmd: The single character command code representing this command.
            key: The name of the header.
            val: The value/data for the header.
        """
        (key, val) = data.split('\0', 1)
        return (cmd, key, val)

    def _ParseEndHeaders(self, cmd, data):
        """Parse the 'EndHeaders' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple (cmd) where:
            cmd: The single character command code representing this command.
        """
        return (cmd)

    def _ParseBody(self, cmd, data):
        """Parse the 'Body' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple (cmd, data) where:
            cmd : The single character command code representing this command.
            data: TODO: parse this better
        """
        return (cmd, data)

    def _ParseEndBody(self, cmd, data):
        """Parse the 'EndBody' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: No data is sent for this command.

        Returns:
          A tuple (cmd) where:
            cmd: The single character command code representing this command.
        """
        return (cmd)

    def _ParseQuit(self, cmd, data):
        """Parse the 'Quit' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple (cmd) where:
            cmd: The single character command code representing this command.
        """
        return (cmd)

    def _ParseAbort(self, cmd, data):
        """Parse the 'Abort' milter data into arguments for the milter handler.

        Args:
          cmd: A single character command code representing this command.
          data: Command-specific milter data to be unpacked/parsed.

        Returns:
          A tuple (cmd) where:
            cmd: The single character command code representing this command.
        """
        return (cmd)

    def _ParseData(self, cmd, data):
        # print "pdata: cmd=%s data=%s"%(cmd,data)
        return (cmd, data)


class PpyMilter(object):

    """Pure python milter handler base class.  Inherit from this class
    and override any On*() commands you would like your milter to handle.
    Register any actions your milter may perform using the Can*() functions
    during your __init__() (after calling PpyMilter.__init()__!) to ensure
    your milter's actions are accepted.

    Pass a reference to your handler class to a python milter socket server
    (e.g. AsyncPpyMilterServer) to create a stand-alone milter
    process than invokes your custom handler.
    """

    # Actions we tell sendmail we may perform
    # PpyMilter users invoke self.CanFoo() during their __init__()
    # to toggle these settings.
    ACTION_ADDHDRS = 1  # 0x01 SMFIF_ADDHDRS    # Add headers
    ACTION_CHGBODY = 2  # 0x02 SMFIF_CHGBODY    # Change body chunks
    ACTION_ADDRCPT = 4  # 0x04 SMFIF_ADDRCPT    # Add recipients
    ACTION_DELRCPT = 8  # 0x08 SMFIF_DELRCPT    # Remove recipients
    ACTION_CHGHDRS = 16  # 0x10 SMFIF_CHGHDRS    # Change or delete headers
    ACTION_QUARANTINE = 32  # 0x20 SMFIF_QUARANTINE # Quarantine message

    def __init__(self):
        """Construct a PpyMilter object.  Sets callbacks and registers
        callbacks.  Make sure you call this directly "PpyMilter.__init__(self)"
        at the beginning of your __init__() if you override the class constructor!

        """
        self.__actions = 0
        self.__protocol = NO_CALLBACKS
        for (callback, flag) in CALLBACKS.items():
            if hasattr(self, callback):
                self.__protocol &= ~flag

    def Accept(self):
        """Create an 'ACCEPT' response to return to the milter dispatcher."""
        return RESPONSE['ACCEPT']

    def Reject(self):
        """Create a 'REJECT' response to return to the milter dispatcher."""
        return RESPONSE['REJECT']

    def Discard(self):
        """Create a 'DISCARD' response to return to the milter dispatcher."""
        return RESPONSE['DISCARD']

    def TempFail(self):
        """Create a 'TEMPFAIL' response to return to the milter dispatcher."""
        return RESPONSE['TEMPFAIL']

    def Continue(self):
        """Create an '' response to return to the milter dispatcher."""
        return RESPONSE['CONTINUE']

    def CustomReply(self, code, text):
        """Create a 'REPLYCODE' (custom) response to return to the milter
        dispatcher.

        Args:
          code: Integer or digit string (should be \d\d\d).  NOTICE: A '421' reply
                code will cause sendmail to close the connection after responding!
                (https://www.sendmail.org/releases/8.13.0.html)
          text: Code reason/explaination to send to the user.
        """
        return '%s%s %s\0' % (RESPONSE['REPLYCODE'], code, text)

    def AddRecipient(self, rcpt):
        """Construct an ADDRCPT reply that the client can send during OnEndBody.

        Args:
          rcpt: The recipient to add, should have <> around it.
        """
        self.__VerifyCapability(self.ACTION_ADDRCPT)
        return '%s%s\0' % (RESPONSE['ADDRCPT'], rcpt)

    def AddHeader(self, name, value):
        """Construct an ADDHEADER reply that the client can send during OnEndBody.

        Args:
          name: The name of the header to add
          value: The value of the header
        """
        self.__VerifyCapability(self.ACTION_ADDHDRS)
        return '%s%s\0%s\0' % (RESPONSE['ADDHEADER'], name, value)

    def DeleteRecipient(self, rcpt):
        """Construct an DELRCPT reply that the client can send during OnEndBody.

        Args:
          rcpt: The recipient to delete, should have <> around it.
        """
        self.__VerifyCapability(self.ACTION_DELRCPT)
        return '%s%s\0' % (RESPONSE['DELRCPT'], rcpt)

    def InsertHeader(self, index, name, value):
        """Construct an INSHEADER reply that the client can send during OnEndBody.

        Args:
          index: The index to insert the header at. 0 is above all headers.
                 A number greater than the number of headers just appends.
          name: The name of the header to insert.
          value: The value to insert.
        """
        self.__VerifyCapability(self.ACTION_ADDHDRS)
        index = struct.pack('!I', index)
        return '%s%s%s\0%s\0' % (RESPONSE['INSHEADER'], index, name, value)

    def ChangeHeader(self, index, name, value):
        """Construct a CHGHEADER reply that the client can send during OnEndBody.

        Args:
          index: The index of the header to change, offset from 1.
                 The offset is per-occurance of this header, not of all headers.
                 A value of '' (empty string) will cause the header to be deleted.
          name: The name of the header to insert.
          value: The value to insert.
        """
        self.__VerifyCapability(self.ACTION_CHGHDRS)
        index = struct.pack('!I', index)
        return '%s%s%s\0%s\0' % (RESPONSE['CHGHEADER'], index, name, value)

    def ReturnOnEndBodyActions(self, actions):
        """Construct an OnEndBody response that can consist of multiple actions
        followed by a final required Continue().

        All message mutations (all adds/changes/deletes to envelope/header/body)
        must be sent as response to the OnEndBody callback.  Multiple actions
        are allowed.  This function formats those multiple actions into one
        response to return back to the PpyMilterDispatcher.

        For example to make sure all recipients are in 'To' headers:
        +---------------------------------------------------------------------
        | class NoBccMilter(PpyMilterBase):
        |  def __init__(self):
        |    self.__mutations = []
        |    ...
        |  def OnRcptTo(self, cmd, rcpt_to, esmtp_info):
        |    self.__mutations.append(self.AddHeader('To', rcpt_to))
        |    return self.Continue()
        |  def OnEndBody(self, cmd):
        |    tmp = self.__mutations
        |    self.__mutations = []
        |    return self.ReturnOnEndBodyActions(tmp)
        |  def OnResetState(self):
        |    self.__mutations = []
        +---------------------------------------------------------------------

        Args:
          actions: List of "actions" to perform on the message.
                   For example:
                     actions=[AddHeader('Cc', 'lurker@example.com'),
                              AddRecipient('lurker@example.com')]
        """
        return actions[:] + [self.Continue()]

    def __ResetState(self):
        """Clear out any per-message data.

        Milter connections correspond to SMTP connections, and many messages may be
        sent in the same SMTP conversation. Any data stored that pertains to the
        message that was just handled should be cleared so that it doesn't affect
        processing of the next message. This method also implements an
        'OnResetState' callback that milters can use to catch this situation too.
        """
        try:
            self.OnResetState()
        except AttributeError:
            logging.warn(
                'No OnResetState() callback is defined for this milter.')

    # you probably should not be overriding this  :-p
    def OnOptNeg(self, cmd, ver, actions, protocol):
        """Callback for the 'OptNeg' (option negotiation) milter command.
        Shouldn't be necessary to override (don't do it unless you
        know what you're doing).

        Option negotation is based on:
        (1) Command callback functions defined by your handler class.
        (2) Stated actions your milter may perform by invoking the
            "self.CanFoo()" functions during your milter's __init__().
        """
        out = struct.pack('!III', MILTER_VERSION,
                          self.__actions & actions,
                          self.__protocol & protocol)
        return cmd + out

    def OnMacro(self, cmd, macro_cmd, data):
        """Callback for the 'Macro' milter command: no response required."""
        return None

    def OnData(self, cmd, data):
        return self.Continue()

    def OnQuit(self, cmd):
        """Callback for the 'Quit' milter command: close the milter connection.

        The only logical response is to ultimately raise a
        PpyMilterCloseConnection() exception.
        """
        raise PpyMilterCloseConnection('received quit command')

    def OnAbort(self, cmd):
        """Callback for the 'Abort' milter command.

        This callback is required because per-message data must be cleared when an
        Abort command is received. Otherwise any message modifications will end up
        being applied to the next message that is sent down the same SMTP
        connection.

        Args:
          cmd: Unused argument.

        Returns:
          A Continue response so that further messages in this SMTP conversation
          will be processed.
        """
        self.__ResetState()
        return self.Continue()

    def OnEndBody(self, cmd):
        """Callback for the 'EndBody' milter command.

        If your milter wants to do any message mutations (add/change/delete any
        envelope/header/body information) it needs to happen as a response to
        this callback (so need to override this function and cause those
        actions by returning using ReturnOnEndBodyActions() above).

        Args:
          cmd: Unused argument.

        Returns:
          A continue response so that further messages in this SMTP conversation
          will be processed.
        """
        return self.Continue()

    # Call these from __init__() (after calling PpyMilter.__init__()  :-p
    # to tell sendmail you may perform these actions
    # (otherwise performing the actions may fail).
    def CanAddHeaders(self):
        """Register that our milter may perform the action 'ADDHDRS'."""
        self.__actions |= self.ACTION_ADDHDRS

    def CanChangeBody(self):
        """Register that our milter may perform the action 'CHGBODY'."""
        self.__actions |= self.ACTION_CHGBODY

    def CanAddRecipient(self):
        """Register that our milter may perform the action 'ADDRCPT'."""
        self.__actions |= self.ACTION_ADDRCPT

    def CanDeleteRecipient(self):
        """Register that our milter may perform the action 'DELRCPT'."""
        self.__actions |= self.ACTION_DELRCPT

    def CanChangeHeaders(self):
        """Register that our milter may perform the action 'CHGHDRS'."""
        self.__actions |= self.ACTION_CHGHDRS

    def CanQuarantine(self):
        """Register that our milter may perform the action 'QUARANTINE'."""
        self.__actions |= self.ACTION_QUARANTINE

    def __VerifyCapability(self, action):
        if not (self.__actions & action):
            logging.error('Error: Attempted to perform an action that was not' +
                          'requested.')
            raise PpyMilterActionError('Action not requested in __init__')
