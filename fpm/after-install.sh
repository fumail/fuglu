#!/bin/sh
# user setup
if ! getent passwd fuglu > /dev/null; then
    /usr/sbin/adduser --system --group --home /var/lib/fuglu fuglu
fi

# logging directory
/usr/bin/install --directory --owner root --group fuglu --mode 0775 /var/log/fuglu

# adapt the config file
/bin/sed -i \
    -e 's#user=nobody#user=fuglu#' \
    -e 's#group=nobody#group=fuglu#' \
    -e 's#tempdir=/tmp#tempdir=/var/lib/fuglu#' \
    -e 's#port=3310#port=/var/run/clamav/clamd.ctl#' \
    /etc/fuglu/fuglu.conf.dist

# setup default config
find /etc/fuglu/ -name '*.dist' | while read file; do
    new="$(echo "$file" | sed 's/.dist//')"
    if ! test -f "$new"; then
        echo "Copying template file to: $new"
        cp -a "$file" "$new"
    fi
done
