FROM debian:jessie

MAINTAINER O. Schacher <oli@fuglu.org>

RUN apt-get update -qq
RUN apt-get install -qq clamav-daemon spamassassin python-pip git
RUN freshclam
RUN pip install BeautifulSoup python-magic SQLAlchemy nose mock pyspf dnspython ipaddress

ADD checkout-and-run-fuglu-tests.sh /usr/local/bin/checkout-and-run-fuglu-tests.sh

CMD sh /usr/local/bin/checkout-and-run-fuglu-tests.sh