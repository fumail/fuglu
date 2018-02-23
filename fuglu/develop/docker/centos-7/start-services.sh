#!/bin/sh
#running systemd in docker vm doesn't work yet, so we need to start the daemons manually
if [ -z "$(ps -ef | grep -i 'clamd' | tail -n +2)" ]; then 
   echo "clamd not running"
   /usr/sbin/clamd -c /etc/clamd.conf --foreground=yes > clamd.log 2>&1 &
   echo "clamd started, waiting 10 s for service"
   sleep 10
   if [ -z "$(ps -ef | grep -i 'clamd' | tail -n +2)" ]; then 
      echo "************************************"
      echo "** ERROR: clamd still not running **"
      echo "************************************"
      cat clamd.log
      exit 1
   fi
fi
if [ -z "$(ps -ef | grep -i 'spamd' | tail -n +2)" ]; then 
   echo "spamd not running"
   spamd  > spamd.log 2>&1 &
   sleep 5
   echo "spamd started, waiting 5 s for service"
   if [ -z "$(ps -ef | grep -i 'spamd' | tail -n +2)" ]; then 
      echo "************************************"
      echo "** ERROR: spamd still not running **"
      echo "************************************"
      cat spamd.log
      exit 1
   fi
fi
