#!/bin/sh
#build current development version and copy it into running docker instance
cd ../../
rm -Rf fuglu-docker-build
set -e
python setup.py sdist --dist-dir=fuglu-docker-build
docker cp fuglu-docker-build/*.gz fuglu-develop:/fuglu.tar.gz
docker exec -t -i fuglu-develop /usr/local/bin/update-fuglu.sh
