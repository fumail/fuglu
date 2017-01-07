#!/bin/sh
#running systemd in docker vm doesn't work yet, so we need to start the daemons manually
/usr/sbin/clamd -c /etc/clamd.conf --foreground=yes &
spamd &
