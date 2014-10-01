FROM centos:centos7

MAINTAINER O. Schacher <oli@fuglu.org>

RUN yum -y install python-setuptools wget gcc
RUN easy_install supervisor

#Clam
RUN yum install -y http://mirror.switch.ch/ftp/mirror/epel/beta/7/x86_64/epel-release-7-0.2.noarch.rpm
RUN yum install -y clamav clamav-scanner clamav-update
RUN echo "Foreground yes" > /etc/freshclam.conf
RUN echo "DatabaseMirror database.clamav.net" >> /etc/freshclam.conf
RUN freshclam
ADD clamd.conf /etc/clamd.conf
RUN adduser clamav

#Spamassassin
RUN yum install -y spamassassin


#postfix
RUN yum install -y postfix

RUN postconf -e "myorigin = docker.fuglu.org"
RUN postconf -e "content_filter = fuglu_default:[127.0.0.1]:10025" 
RUN postconf -e "fuglu_default_destination_recipient_limit=1"
RUN postconf -e "inet_interfaces = all"
RUN postconf -e "myhostname = docker.fuglu.org"

ADD master.cf.additions /tmp/
RUN cat /tmp/master.cf.additions >> /etc/postfix/master.cf
EXPOSE 25 10025 10026
RUN newaliases

#supervisor config / syslog
RUN easy_install supervisor-stdout syslog-stdout
CMD python -u /usr/bin/supervisord
ADD supervisord.conf /etc/


#FUGLU
RUN yum install -y  tar python-sqlalchemy python-magic 
RUN yum install -y mariadb-devel python-devel 
RUN easy_install MySQL-python BeautifulSoup

RUN mkdir /work
RUN cd /work &&\
 wget http://github.com/gryphius/fuglu/tarball/master -O /work/fuglu.tar.gz &&\
 tar -xvzf fuglu.tar.gz &&\
 cd *fuglu-*/fuglu/ &&\
 python setup.py install

RUN mkdir -p /usr/local/fuglu/plugins && chown -R nobody:nobody /usr/local/fuglu
RUN for file in /etc/fuglu/*.dist; do mv "$file" "/etc/fuglu/`basename -s .dist $file `" ; done
ADD logging.conf /etc/fuglu/logging.conf


