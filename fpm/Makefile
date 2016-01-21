GEM_BINDIR = .gem-bin/
FPM_BIN = $(GEM_BINDIR)fpm 
GIT_BIN = /usr/bin/git
PACKAGE = fuglu

all: deb

# debian package from latest version on pypi
deb: clean fpm
	$(FPM_BIN) -s python -t deb \
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

# aliases to helper tools
fpm: $(FPM_BIN)
git: $(GIT_BIN)

# helper tools
$(FPM_BIN):
	sudo apt-get install -y -qq ruby-dev build-essential python-setuptools
	mkdir -p $(GEM_BINDIR)
	gem install --no-ri --no-rdoc --user-install --bindir $(GEM_BINDIR) fpm

$(GIT_BIN):
	sudo apt-get install -y -qq git

# meta targets
clean:
	rm -f *.deb

mrproper: clean
	rm -rf $(GEM_BINDIR)
