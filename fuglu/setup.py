from distutils.core import setup, Command
import glob
import sys
import os
sys.path.insert(0, 'src')

# store old content of version file here
# if we have git available, temporarily overwrite the file
# so we can report the git commit id in fuglu --version
OLD_VERSFILE_CONTENT = None
VERSFILE = 'src/fuglu/__init__.py'


def git_version():
    from fuglu import FUGLU_VERSION
    global VERSFILE, OLD_VERSFILE_CONTENT
    try:
        import subprocess
        x = subprocess.Popen(
            ['git', 'describe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ret = x.wait()
        if ret == 0:
            stdout, stderr = x.communicate()
            vers = stdout.strip()
            # replace fuglu version in file
            if os.path.isfile(VERSFILE):
                OLD_VERSFILE_CONTENT = open(VERSFILE, 'r').read()
                buff = OLD_VERSFILE_CONTENT.replace(FUGLU_VERSION, vers)
                open(VERSFILE, 'w').write(buff)
            return vers
        else:
            return FUGLU_VERSION
    except Exception as e:
        return FUGLU_VERSION


setup(name="fuglu",
      version=git_version(),
      description="Fuglu Mail Content Scanner",
      author="O. Schacher",
      url='http://www.fuglu.org',
      download_url='http://github.com/gryphius/fuglu/tarball/master',
      author_email="oli@fuglu.org",
      package_dir={'': 'src'},
      packages=['fuglu', 'fuglu.plugins', 'fuglu.extensions',
                'fuglu.lib', 'fuglu.connectors'],
      scripts=["src/startscript/fuglu", "src/tools/fuglu_debug",
               "src/tools/fuglu_control", "src/tools/fuglu_conf", "src/tools/fuglu_suspectfilter"],
      long_description="""Fuglu is  a modular pre/after queue content filter written in python. It can be used to filter spam, viruses, unwanted attachments etc..

see http://gryphius.github.com/fuglu/ for more details.""",
      data_files=[
          ('/etc/fuglu', glob.glob('conf/*.dist')),
          ('/etc/fuglu/templates', glob.glob('conf/templates/*.dist')),
          ('/etc/fuglu/rules', glob.glob('conf/rules/*.dist')),
      ],

      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: No Input/Output (Daemon)',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Topic :: Communications :: Email',
          'Topic :: Communications :: Email :: Filters',
          'Topic :: Communications :: Email :: Mail Transport Agents',
      ],
      )

# cleanup
if OLD_VERSFILE_CONTENT != None:
    open(VERSFILE, 'w').write(OLD_VERSFILE_CONTENT)
