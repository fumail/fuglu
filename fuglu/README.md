# README for fuglu docker image
Dockerfile to create fuglu test environment image

Based on danBLA/fuglutestenv docker image DockerfilePy2/3 create an image which :
- contains a working fuglu (Python2/3) instance with default configuration
- starts clamd, spamd and fuglu if run without arguments
- exposes ports 10025 10026 10888

The following docker containers are autobuilt and available at docker hub:
- danbla/fuglupy3
  - fuglu in Python3
  - built from github master branch
- danbla/fuglupy3:develop
  - fuglu in Python3
  - built from github develop branch
- danbla/fuglupy2
  - fuglu in Python2
  - built from github master branch
- danbla/fuglupy2:develop
  - fuglu in Python2
  - built from github develop branch
