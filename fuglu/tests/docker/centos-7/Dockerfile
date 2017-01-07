FROM centos:centos7

MAINTAINER O. Schacher <oli@fuglu.org>

RUN yum  -y install epel-release
RUN yum  -y install clamav clamav-scanner clamav-update clamav-data spamassassin python-magic git python-beautifulsoup python-setuptools python-nose unar python-sqlalchemy python-pip
#unfortunately, unrar is no longer available in EPEL https://github.com/gryphius/fuglu/issues/87
RUN yum -y install ftp://ftp.pbone.net/mirror/ftp5.gwdg.de/pub/opensuse/repositories/home:/Kenzy:/modified:/C7/CentOS_7/x86_64/unrar-5.0.12-2.1.x86_64.rpm
RUN pip install rarfile mock dkimpy dnspython pydns pyspf ipaddr
ADD freshclam.conf /etc/freshclam.conf
ADD clamd.conf /etc/clamd.conf
RUN adduser clamav && freshclam
ADD start-services.sh /usr/local/bin/start-services.sh
CMD /bin/bash
VOLUME /fuglu-src


