#!/bin/bash
# run current fuglu source in a docker environment
srcdir=$(cd "$(dirname "$0")/../../"; pwd)
folder=${1:-"centos-7"}


echo "sourcedir: $srcdir"

ex=0


echo ""
echo "***************************************************************"
echo "* Running fuglu in docker instance for $folder"
echo "***************************************************************"
image=fuglu-test-$folder
docker build -t=$image $srcdir/develop/docker/$folder
if [ $? -gt 0 ]; then
 echo "Image build failed"
 exit 1
fi

did=$(docker create -w /fuglu-src -v $srcdir:/fuglu-src:ro -t -i $image /bin/bash)
echo "Starting docker instance ID: $did"
docker start $did
echo "Starting services (clamav, SA)..."
docker exec -d $did sh /usr/local/bin/start-services.sh

echo "Installing current fuglu source"
docker exec -i $did python setup.py build -b /tmp/build install

echo "Writing default config"
docker exec -i $did rename '.dist' '' /etc/fuglu/*.dist
docker exec -i $did mkdir /var/log/fuglu
docker exec -i $did chown nobody /var/log/fuglu

echo "Entering the fuglu docker environment. Exit using ctrl-D"

docker exec -ti $did /bin/bash

echo "Left the fuglu docker environment. To re-enter: "
echo "docker exec -ti $did /bin/bash"
echo ""
echo "Cleanup when you are done: "
echo "docker kill $did "
echo "docker rm -v $did "
echo ""

