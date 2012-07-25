from distutils.core import setup, Command
import glob
import sys
import os
sys.path.insert(0,'src')

#store old content of version file here
#if we have git available, temporarily overwrite the file
#so we can report the git commit id in fuglu --version 
OLD_VERSFILE_CONTENT=None
VERSFILE='src/fuglu/__init__.py'

def git_version():
    from fuglu import FUGLU_VERSION
    global VERSFILE,OLD_VERSFILE_CONTENT
    try:
        import subprocess
        x=subprocess.Popen(['git','describe'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        ret=x.wait()
        if ret==0:
            stdout,stderr=x.communicate()
            vers=stdout.strip()
            #replace fuglu version in file
            if os.path.isfile(VERSFILE):
                OLD_VERSFILE_CONTENT=open(VERSFILE,'r').read()
                buff=OLD_VERSFILE_CONTENT.replace(FUGLU_VERSION,vers)
                open(VERSFILE,'w').write(buff)
            return vers
        else:
            return FUGLU_VERSION
    except Exception,e:
        return FUGLU_VERSION


setup(name = "fuglu",
    version = git_version(),
    description = "Fuglu Mail Content Scanner",
    author = "O. Schacher",
    url='http://www.fuglu.org',
    author_email = "oli@fuglu.org",
    package_dir={'':'src'},
    packages = ['fuglu','fuglu.plugins','fuglu.extensions','fuglu.lib','fuglu.connectors'],
    scripts = ["src/startscript/fuglu","src/tools/fuglu_debug","src/tools/fuglu_control","src/tools/fuglu_conf"],
    long_description = """Fuglu Mail Content Scanner""" ,
    data_files=[
                ('/etc/fuglu',glob.glob('conf/*.dist')),
                ('/etc/fuglu/templates',glob.glob('conf/templates/*.dist')),
                ('/etc/fuglu/rules',glob.glob('conf/rules/*.dist')),
                ]
)

#cleanup
if OLD_VERSFILE_CONTENT!=None:
    open(VERSFILE,'w').write(OLD_VERSFILE_CONTENT)
    


class DistroDefault(Command):
    description = "install distribuction specific init scripts and default config"
    user_options = []
    
    def initialize_options(self):
        pass
        
        
    def finalize_options(self):
        self.distroalias={
            'arch':'arch',
            'debian':'debian',
            'ubuntu':'debian',
            'mint':'debian',
            'rhel':'rhel',
            'centos':'rhel',
        }
        self.distro,self.version=self.detect_distro()
        
    def run(self):
        assert self.distro!=None,"could not detect distribution"
        if self.distro not in self.distroalias:
            print "sorry, no defaults"
    
    def detect_distro(self):
        """returns a distribution name and version number if possible"""
        pass
        
        
        