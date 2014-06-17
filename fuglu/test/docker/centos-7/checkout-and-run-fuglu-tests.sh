#!/bin/sh
#running systemd in docker vm doesn't work yet, so we need to start the daemons manually
clamd &
spamd & 
cd /tmp/
git clone https://github.com/gryphius/fuglu.git
cd fuglu/fuglu/test
python runtests.py
