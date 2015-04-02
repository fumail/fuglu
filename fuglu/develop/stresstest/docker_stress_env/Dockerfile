FROM debian:wheezy
MAINTAINER O. Schacher <oli@fuglu.org>

#default cmd
CMD ["/usr/local/bin/fuglu", "-f"]

RUN apt-get update -qq

#required (automatically installs python)
RUN apt-get install -qq  python-magic libmagic1

#clamav
RUN apt-get install -qq clamav-daemon
RUN freshclam
RUN mkdir /var/run/clamav && chown clamav.clamav /var/run/clamav
RUN sed -i 's/Foreground false/Foreground true/' /etc/clamav/clamd.conf
CMD ["bash","-c", "/usr/sbin/clamd & /usr/local/bin/fuglu -f"]

RUN mkdir -p /etc/fuglu/conf.d
ADD logging.conf /etc/fuglu/logging.conf
ADD fuglu.conf /etc/fuglu/fuglu.conf
EXPOSE 10025


ADD fuglu.tar.gz /tmp/newfuglu
RUN cd /tmp/newfuglu/fuglu-* && python setup.py install
