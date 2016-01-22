GEMDIR = .gems/
FPM_BIN = $(GEMDIR)bin/fpm 
GIT_BIN = /usr/bin/git
PACKAGE = fuglu

all: deb

# debian package from latest version on pypi
deb: clean fpm
	GEM_HOME=$(GEMDIR) $(FPM_BIN) -s python -t deb \
		-d python-magic \
		-d libmagic1 \
		-d python-beautifulsoup \
		-d spamassassin \
		-d clamav-daemon \
		--after-install after-install.sh \
		$(PACKAGE)

# debian package from current checkout
deb-checkout: PACKAGE = ../fuglu/setup.py
deb-checkout: clean git deb

deb-rarfile: fpm
	GEM_HOME=$(GEMDIR) $(FPM_BIN) -s python -t deb \
		rarfile

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
	rm -f *.deb

mrproper: clean
	rm -rf $(GEMDIR)
