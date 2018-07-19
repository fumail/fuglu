#!/bin/bash

# rename if target conf file is not present
allFiles=(`find /etc/fuglu/. -iname '*.dist'`)
for file in "${allFiles[@]}"
do
   newName=`basename -s .dist $file`
   dir=`dirname $file`
   newFile="$dir/$newName"
   echo "Copy $file to $newFile"
   mv -n $file $newFile
done

# default log folder
mkdir -p /var/log/fuglu
chown -fR nobody /var/log/fuglu
chmod -fR u=rwx,g=rwx,o=rwx /var/log/fuglu
