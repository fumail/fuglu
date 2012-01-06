from distutils.core import setup
import glob
import sys
sys.path.insert(0,'src')
from fuglu import FUGLU_VERSION

setup(name = "fuglu",
    version = FUGLU_VERSION,
    description = "Fuglu Mail Content Scanner",
    author = "O. Schacher",
    url='http://www.fuglu.org',
    author_email = "oli@fuglu.org",
    package_dir={'':'src'},
    packages = ['fuglu','fuglu.plugins','fuglu.extensions','fuglu.lib','fuglu.connectors'],
    scripts = ["src/startscript/fuglu","src/tools/fuglu_debug","src/tools/fuglu_control"],
    long_description = """Fuglu Mail Content Scanner""" ,
    data_files=[
                ('/etc/fuglu',glob.glob('conf/*.dist')),
                ('/etc/fuglu/templates',glob.glob('conf/templates/*.dist')),
                ('/etc/fuglu/rules',glob.glob('conf/rules/*.dist')),
                ]
)
