# README for fuglu docker image
Dockerfile to create fuglu test environment image

Based on danBLA/fuglutestenv docker image this Dockerfile creates an image which :

- contains a working fuglu (Python2/3) instance with default configuration
- starts clamd, spamd and fuglu if run without arguments
- exposes ports 25 10025 10026 10888
