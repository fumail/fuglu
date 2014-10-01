#!/bin/sh
service clamd start
service spamassassin start
cd /tmp/
git clone https://github.com/gryphius/fuglu.git
cd fuglu
nosetests fuglu/tests/unit/ fuglu/tests/integration/
