#!/bin/sh
/usr/sbin/clamd -c /etc/clamd.conf --foreground=yes &
spamd -d

