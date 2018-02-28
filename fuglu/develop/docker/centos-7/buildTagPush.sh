#!/bin/bash

docker build -t centos-7-fuglu-testenv .
docker tag centos-7-fuglu-testenv localhost:5000/centos-7-fuglu-testenv 
docker push localhost:5000/centos-7-fuglu-testenv
