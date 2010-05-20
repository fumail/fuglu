from distutils.core import setup
import glob


setup(name = "fuglu",
    version = "0.4.5",
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
                ('/etc/init.d',['scripts/init.d-centos/fuglu']),
                ]
)
