#!/bin/sh
docker kill fuglu-develop
docker rm fuglu-develop
docker run -t --name=fuglu-develop -i fuglu-develop
