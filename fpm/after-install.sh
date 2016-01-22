#!/bin/sh
if ! getent passwd fuglu > /dev/null; then
    /usr/sbin/adduser --system --group --home /var/lib/fuglu fuglu
fi
/usr/bin/install --directory --owner root --group fuglu --mode 0775 /var/log/fuglu

/bin/sed -i \
    -e 's#user=nobody#user=fuglu#' \
    -e 's#group=nobody#group=fuglu#' \
    -e 's#tempdir=/tmp#tempdir=/var/lib/fuglu#' \
    -e 's#port=3310#port=/var/run/clamav/clamd.ctl#' \
    /etc/fuglu/fuglu.conf.dist
