#!/bin/sh
service clamd start
service spamassassin start
cd /tmp/
git clone https://github.com/gryphius/fuglu.git
cd fuglu/fuglu/test
python runtests.py
