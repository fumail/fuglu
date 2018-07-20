FROM danbla/fuglutestenv

MAINTAINER danBLA <danBLA@users.noreply.github.com>

WORKDIR /fuglu-src
ADD ../../fuglu /fuglu-src
RUN python2 setup.py install --force
RUN /bin/bash -c develop/docker/auto/init-config-folders.sh

ADD ../../fuglu/develop/docker/auto/start-services.sh /usr/local/bin/start-services.sh 
CMD ["/bin/bash", "-c", "/usr/local/bin/start-services.sh all"]
VOLUME ["/fuglu-src", "/etc/fuglu", "/var/log/fuglu" ]

EXPOSE 10025 10026 10888


