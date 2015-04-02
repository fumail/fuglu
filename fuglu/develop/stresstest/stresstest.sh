#!/bin/sh

#$1 : path to fuglu archive
#$2 : optional --no-cache to force apt-get update 

if [ ! -f $1 ] ; then
 echo "Arg: path/to/fuglu.tar.gz"
 echo "$1 not found"
 exit 1
fi

yell() { echo "$0: $*" >&2; }
die() { yell "$*"; exit 111; }
try() { "$@" || die "cannot $*"; }

SCRIPTPATH=$( cd $(dirname $0) ; pwd -P )

dockerdir="docker_stress_env"

cp $1 $SCRIPTPATH/$dockerdir/fuglu.tar.gz
try docker build $2 -t fuglu_stress $SCRIPTPATH/$dockerdir 
container=`docker run -d -p 10025:10025 fuglu_stress` || exit 1
#check if it worked
#try docker inspect $container
echo "Started container $container"
docker logs -f $container &
echo "Starting stress test in a few seconds..." # clamav needs a bit of time to start up
sleep 15
/usr/local/bin/smtp-source -c -s 30 -m 10000 127.0.0.1:10025
echo "enter docker shell for inspection"
docker exec -t -i $container /bin/bash

echo "press enter to kill the container"
read a
docker kill $container

