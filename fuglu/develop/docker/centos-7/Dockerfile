FROM centos:centos7

MAINTAINER danBLA <danBLA@users.noreply.github.com>

# ssdeep -> see http://python-ssdeep.readthedocs.io/en/latest/installation.html#install-on-centos-7
#        => NOTE: not all versions working...
RUN yum  -y groupinstall "Development Tools"
RUN yum  -y install epel-release
RUN yum  -y install clamav clamav-scanner clamav-update clamav-data spamassassin python-magic git python-beautifulsoup python-setuptools python-nose unar python-sqlalchemy python-pip postfix python34 python34-nose python34-pip libffi-devel python-devel python-pip ssdeep-devel ssdeep-libs python34-devel
#unfortunately, unrar is no longer available in EPEL https://github.com/fumail/fuglu/issues/87
RUN yum -y install ftp://ftp.pbone.net/mirror/ftp5.gwdg.de/pub/opensuse/repositories/home:/Kenzy:/modified:/C7/CentOS_7/x86_64/unrar-5.0.12-2.1.x86_64.rpm
RUN yum update -y
RUN pip2 install --upgrade pip
# ssdeep==3.3 and smaller doesn't work for Python2
RUN pip2 install rarfile mock dkimpy dnspython pydns pyspf ipaddr rednose ssdeep==3.2 redis domainmagic
RUN pip3 install --upgrade pip
RUN pip3 install rarfile rednose  sqlalchemy python-magic pyspf py3dns mock ssdeep redis domainmagic
ADD freshclam.conf /etc/freshclam.conf
ADD clamd.conf /etc/clamd.conf
RUN adduser clamav && freshclam
ADD start-services.sh /usr/local/bin/start-services.sh
CMD /bin/bash
VOLUME /fuglu-src

EXPOSE 25 10025 10026 10888


