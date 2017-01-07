#!/bin/bash
# run unit and integration tests in various docker environments
srcdir=$(cd "$(dirname "$0")/../../"; pwd)
folder=${1:-"centos-7"}


echo "sourcedir: $srcdir"

ex=0


echo ""
echo "***************************************************************"
echo "* Running tests in docker instance for $folder"
echo "***************************************************************"
image=fuglu-test-$folder
docker build -t=$image $folder
if [ $? -gt 0 ]; then
 echo "Image build failed"
 exit 1
fi

did=$(docker create -w /fuglu-src -v $srcdir:/fuglu-src:ro -t -i $image /bin/bash)
echo "Startomg docker instance ID: $did"
docker start $did
echo "Starting services (clamav, SA)..."
docker exec -d $did sh /usr/local/bin/start-services.sh
sleep 10
echo "Startup done, running nose tests..."
docker exec $did nosetests tests/unit tests/integration
result=$?
if [ $result -gt 0 ]; then
    echo "Test failed"
    ex=$result
    echo "Inspect the container with:"
    echo "docker exec -ti $did /bin/bash"
    echo "Remember to remove the container aftewards with:"
    echo "docker kill $did"
    echo "docker rm -v $did"
else
    echo "Test completed ok, cleaning up."
    docker kill $did >/dev/null
    docker rm -v $did >/dev/null
fi
exit $ex
