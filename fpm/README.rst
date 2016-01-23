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
package (such as ubuntu trusty LTS), ``make deb-rarfile``
