FROM centos:centos7

MAINTAINER O. Schacher <oli@fuglu.org>

RUN yum -y install http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-1.noarch.rpm
RUN yum -y install clamav clamav-scanner clamav-update clamav-freshclam clamav-data spamassassin python-magic git python-beautifulsoup python-setuptools
RUN easy_install sqlalchemy
ADD freshclam.conf /etc/freshclam.conf
ADD checkout-and-run-fuglu-tests.sh /usr/local/bin/checkout-and-run-fuglu-tests.sh
ADD clamd.conf /etc/clamd.conf

RUN adduser clamav && freshclam
CMD sh /usr/local/bin/checkout-and-run-fuglu-tests.sh
