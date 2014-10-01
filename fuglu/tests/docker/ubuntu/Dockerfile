FROM ubuntu

MAINTAINER O. Schacher <oli@fuglu.org>

RUN sudo apt-get update -qq
RUN sudo apt-get install -qq clamav-daemon spamassassin python-pip git
RUN sudo freshclam
RUN pip install BeautifulSoup python-magic SQLAlchemy

ADD checkout-and-run-fuglu-tests.sh /usr/local/bin/checkout-and-run-fuglu-tests.sh

CMD sh /usr/local/bin/checkout-and-run-fuglu-tests.sh