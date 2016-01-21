Build fuglu packages for various package managers using fpm



#PATH=$PATH:.gem/ruby/1.9.1/bin
#fpm -s python -t deb -d python-magic -d libmagic1 -d python-beautifulsoup -d spamassassin -d clamav-daemon --after-install after-install.sh fuglu

clean:
    rm -f *.deb

mrproper: clean
    
