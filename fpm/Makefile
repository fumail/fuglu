GEMDIR = .gems/
FPM_BIN = $(GEMDIR)bin/fpm 
GIT_BIN = /usr/bin/git
PACKAGE = fuglu

all: deb

# debian package from latest version on pypi
deb: clean fpm
	GEM_HOME=$(GEMDIR) $(FPM_BIN) -s python -t deb \
		--depends python-magic \
		--depends libmagic1 \
		--depends python-beautifulsoup \
		--depends spamassassin \
		--depends clamav-daemon \
		--deb-suggests python-sqlalchemy \
		--deb-suggests python-rarfile \
		--deb-init ../fuglu/scripts/startscripts/debian/7/fuglu \
		--after-install after-install.sh \
		$(PACKAGE)

# debian package from current checkout
deb-checkout: PACKAGE = ../fuglu/setup.py
deb-checkout: clean git deb

# rarfile package is not available on all supported ubuntu versions
deb-rarfile: clean fpm
	GEM_HOME=$(GEMDIR) $(FPM_BIN) -s python -t deb \
		rarfile

rpm: clean fpm
	sudo apt-get install -y -qq rpm
	GEM_HOME=$(GEMDIR) $(FPM_BIN) -s python -t rpm \
		--depends python-magic \
		--depends file-libs \
		--depends python-beautifulsoup4 \
		--depends spamassassin \
		--depends clamav-server \
		--depends clamav-server-systemd \
		--rpm-init ../fuglu/scripts/startscripts/centos_rhel/7/fuglu.service \
		--after-install after-install.sh \
		$(PACKAGE)

# rom package from current checkout
rpm-checkout: PACKAGE = ../fuglu/setup.py
rpm-checkout: clean git deb

# aliases to helper tools
fpm: $(FPM_BIN)
git: $(GIT_BIN)

# helper tools
$(FPM_BIN):
	sudo apt-get install -y -qq ruby-dev build-essential python-setuptools
	mkdir -p $(GEMDIR)
	gem install --no-ri --no-rdoc --install-dir $(GEMDIR) fpm

$(GIT_BIN):
	sudo apt-get install -y -qq git

# meta targets
clean:
	rm -f *.deb *.rpm

mrproper: clean
	rm -rf $(GEMDIR)
