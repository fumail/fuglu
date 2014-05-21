#!/bin/sh
service clamav-daemon start
spamd -d
cd /tmp/
git clone https://github.com/gryphius/fuglu.git
cd fuglu/fuglu/test
python runtests.py
