#!/bin/sh
/usr/sbin/adduser --quiet --system --group --home /var/lib/fuglu fuglu
/usr/bin/install --directory --owner root --group fuglu --mode 0775 /var/log/fuglu
