#!/usr/bin/env python
import smtplib
import sys
smtpServer = smtplib.SMTP('127.0.0.1',10888)

smtpServer.set_debuglevel(1)
smtpServer.helo('olis.filter')
fh=open(sys.argv[1])

message=fh.read()

smtpServer.sendmail('sender@unittests.fuglu.org', 'recipient@unittests.fuglu.org', message)
smtpServer.quit()
