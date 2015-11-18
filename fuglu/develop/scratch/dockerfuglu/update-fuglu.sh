#!/bin/sh
cd / && tar -xvzf fuglu.tar.gz && cd fuglu-* && python setup.py install && killall fuglu
