Build FuGlu packages
====================

The contents of this directory allow you to build packages for various
operating systems from FuGlu source. It uses ``fpm`` to create packages from
pypi, or local source code.

To use it, basically open a console at this directory, and run
a ``make <target>`` command. It assumes that your OS is debian(-based).
If you have something else, you can use a simple VM (f.i. a clean
vagrant `ubuntu/trusty64` box) for the build process.

-------------
Debian/Ubuntu
-------------

Running ``make deb`` will result in a package for the latest FuGlu release
listed on the PyPi website, f.i: ``python-fuglu_0.6.5_all.deb``

Running ```make deb-checkout`` will create a package from the currently
checked out source tree, with the specific git-tagged version number, 
f.i: ``python-fuglu_0.6.5-52-gcfb8990_all.deb``

Finally, if you're using a ubuntu or debian version that has no ``python-rarfile``
package (an optional dependency), ``make deb-rarfile`` will give you
what you need.

-----------
RHEL/CentOS
-----------

Running ``make rpm`` will give you a ``python-fuglu-0.6.5-1.noarch.rpm``.
For a package based on the current git tree, use ``make rpm-checkout``.
In order to install, you'll need additional dependencies (clamav-server,
python-beautifulsoup4) from EPEL.
