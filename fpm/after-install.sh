#!/bin/sh
if ! getent passwd fuglu > /dev/null; then
    /usr/sbin/adduser --system --group --home /var/lib/fuglu fuglu
fi
/usr/bin/install --directory --owner root --group fuglu --mode 0775 /var/log/fuglu
