FROM debian:wheezy

MAINTAINER O. Schacher <oli@fuglu.org>

RUN apt-get update -qq
RUN apt-get install -qq  python-magic libmagic1
RUN mkdir -p /etc/fuglu/conf.d
ADD old.tar.gz /tmp/oldfuglu


ADD logging.conf /etc/fuglu/logging.conf
ADD fuglu.conf /etc/fuglu/fuglu.conf

EXPOSE 10025
CMD ["/usr/local/bin/fuglu", "-f"]



#install old fuglu - we can simulate the crash with this version
#RUN cd /tmp/oldfuglu/fuglu-* && python setup.py install && fuglu --lint

#install new fuglu - crash should not happen anymore
ADD new.tar.gz /tmp/newfuglu
RUN cd /tmp/newfuglu/fuglu-* && python setup.py install && fuglu --lint
