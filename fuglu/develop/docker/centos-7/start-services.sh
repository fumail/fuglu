#!/bin/sh
#running systemd in docker vm doesn't work yet, so we need to start the daemons manually

wait_for_file () {
   if [ -z "$1" ];  then
      echo "wait_for_file: 1st argument is missing!"
      exit 1
   fi

   if [ -z "$2" ];  then
      echo "wait_for_file: 2nd argument is missing!"
      exit 1
   fi

   if [ -z "$3" ];  then
      echo "wait_for_file: 3nd argument is missing!"
      exit 1
   fi

   counter=0
   maxcounter=$2
   while ! [ -s $1 ] && [ $counter -lt $maxcounter ] ; do
      echo "waiting... $3 secs [$counter/$maxcounter]"
      let counter=counter+1
      sleep $3
   done
   if ! [ $counter -lt $maxcounter ]; then
      echo "time limit reached!"
      exit 1
   fi
   echo "file $1 is not empty"
   cat $1
}



createlog=1
if [ "$1" = "nolog" ];  then
   echo "no log file will be created and no wait operation performed"
   let createlog=0
fi

if [ -z "$(ps -ef | grep -i 'clamd' | tail -n +2)" ]; then 
   echo "clamd not running"

   if [ $createlog -eq 1 ]; then
      /usr/sbin/clamd -c /etc/clamd.conf --foreground=yes > clamd.log 2>&1 &
      # wait for something to apper in the log file
      # args: filename, number of tries, time to wait between tries
      wait_for_file clamd.log 12 5
   else
      /usr/sbin/clamd -c /etc/clamd.conf --foreground=yes > /dev/null 2>&1 &
   fi
else
   echo "clamd is already running..."
fi

if [ -z "$(ps -ef | grep -i 'spamd' | tail -n +2)" ]; then 
   echo "spamd not running"

   if [ $createlog -eq 1 ]; then
      spamd  > spamd.log 2>&1 &
      # wait for something to apper in the log file
      # args: filename, number of tries, time to wait between tries
      wait_for_file spamd.log 12 5
   else
      spamd  > /dev/null 2>&1 &
   fi
else
   echo "spamd is already running..."
fi
