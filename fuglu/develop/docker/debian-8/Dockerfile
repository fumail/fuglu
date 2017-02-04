FROM debian:jessie

MAINTAINER O. Schacher <oli@fuglu.org>

RUN sed -i 's/main/main contrib non-free/g' /etc/apt/sources.list
RUN apt-get update -qq
RUN apt-get install -qq clamav-daemon spamassassin python-pip git unrar
RUN freshclam
RUN pip install BeautifulSoup python-magic SQLAlchemy nose mock pyspf dnspython ipaddr pydns rarfile
ADD start-services.sh /usr/local/bin/start-services.sh
CMD /bin/bash
VOLUME /fuglu-src
ADD clamd.conf /etc/clamd.conf

EXPOSE 25 10025 10026 10888

