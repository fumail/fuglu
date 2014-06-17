FROM h0tbird/centos-7-rc:20140614

MAINTAINER O. Schacher <oli@fuglu.org>

RUN rpm --import http://apt.sw.be/RPM-GPG-KEY.dag.txt
RUN yum -y install http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.3-1.el7.rf.x86_64.rpm
RUN yum -y install clamd spamassassin python-magic git python-beautifulsoup python-setuptools
RUN freshclam
RUN easy_install sqlalchemy

ADD checkout-and-run-fuglu-tests.sh /usr/local/bin/checkout-and-run-fuglu-tests.sh

CMD sh /usr/local/bin/checkout-and-run-fuglu-tests.sh
