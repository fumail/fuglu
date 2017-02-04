#!/bin/bash
# run current fuglu source in a docker environment
srcdir=$(cd "$(dirname "$0")/../../"; pwd)
folder="centos-7"
image=fuglu-test-$folder
docker build -t=$image $srcdir/develop/docker/$folder
if [ $? -gt 0 ]; then
 echo "Image build failed"
 exit 1
fi

did=$(docker create -w /fuglu-src -v $srcdir:/fuglu-src:ro -t -i $image /bin/bash)
echo "Starting docker instance ID: $did"
docker start $did
echo "Installing current fuglu source"
docker exec -i $did python setup.py build_py -d /tmp/build install
echo "Writing default config"
docker exec -i $did rename '.dist' '' /etc/fuglu/*.dist
docker exec -i $did mkdir /var/log/fuglu
docker exec -i $did chown nobody /var/log/fuglu

echo "Writing stresstest config.."
docker cp fuglu.conf $did:/etc/fuglu/fuglu.conf
docker cp logging.conf $did:/etc/fuglu/logging.conf

echo "Starting fuglu in docker..."
docker exec -d $did fuglu


echo "Installing smtp-source stresstest er"

docker exec -i $did yum install -y postfix

NUMMESSAGES=10000
echo "Running stresstest with $NUMMESSAGES messages"
docker exec -i $did bash -c "time smtp-source -c -s 10 -m $NUMMESSAGES 127.0.0.1:10025"
docker exec -i $did bash -c "fuglu_control stats"

echo "Left the fuglu docker environment. To re-enter: "
echo "docker exec -ti $did /bin/bash"
echo ""
echo "Cleanup when you are done: "
echo "docker kill $did "
echo "docker rm -v $did "
echo ""

