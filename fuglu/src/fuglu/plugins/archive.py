#   Copyright 2009-2016 Oli Schacher
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
from fuglu.shared import ScannerPlugin, DELETE, DUNNO, DEFER, SuspectFilter,\
    apply_template
import os
import shutil
import pwd
import grp


class ArchivePlugin(ScannerPlugin):

    """This plugins stores a copy of the message if it matches certain criteria (Suspect Filter). 
You can use this if you want message archives for your domains or to debug problems occuring only for certain recipients.

Examples for the archive.regex filter file:

Archive messages to domain ''test.com'':

``to_domain test\.com``


Archive messages from oli@fuglu.org:


``envelope_from oli@fuglu\.org``


you can also append "yes" and "no" to the rules to create a more advanced configuration. Lets say we want to archive all messages to sales@fuglu.org and all regular messages support@fuglu.org except the ones created by automated scripts like logwatch or daily backup messages etc.

envelope_from logwatch@.*fuglu.org   no

envelope_to sales@fuglu\.org yes

from backups@fuglu.org no

envelope_to support@fuglu\.org      yes


Note: The first rule to match in a message is the only rule that will be applied. Exclusion rules should therefore be put above generic/catch-all rules.
"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)

        self.requiredvars = {
            'archiverules': {
                'default': '/etc/fuglu/archive.regex',
                'description': 'Archiving SuspectFilter File',
            },

            'archivedir': {
                'default': '/tmp',
                'description': 'storage for archived messages',
            },
            'subdirtemplate': {
                'default': '${to_domain}',
                'description': 'subdirectory within archivedir',
            },
            'filenametemplate': {
                'default': '${id}.eml',
                'description': 'filename template for the archived messages',
            },
            'storeoriginal': {
                'default': '1',
                'description': "if true/1/yes: store original message\nif false/0/no: store message probably altered by previous plugins, eg with spamassassin headers",
            },
            'chown': {
                'default': '',
                'description': "change owner of saved messages (username or numeric id) - this only works if fuglu is running as root (which is NOT recommended)",
            },
            'chgrp': {
                'default': '',
                'description': "change group of saved messages (groupname or numeric id) - the user running fuglu must be a member of the target group for this to work",
            },
            'chmod': {
                'default': '',
                'description': "set file permissions of saved messages",
            },

        }

        self.filter = None
        self.logger = self._logger()

    def __str__(self):
        return "Archive"

    def lint(self):
        allok = (
            self.checkConfig() and self.check_deprecated() and self.lint_dirs() and self.lint_filter())
        return allok

    def check_deprecated(self):
        if self.config.has_option(self.section, 'makedomainsubdir'):
            print(
                "the config option 'makedomainsubdir' has been replaced with 'subdirtemplate' ")
            print("please update your config")
            print("makedomainsubdir=1 -> subdirtemplate=${to_domain}")
            print("makedomainsubdir=0 -> subdirtemplate=")
            return False
        return True

    def lint_filter(self):
        filterfile = self.config.get(self.section, 'archiverules')
        filter = SuspectFilter(filterfile)
        return filter.lint()

    def lint_dirs(self):
        archivedir = self.config.get(self.section, 'archivedir')
        if archivedir == "":
            print('Archivedir is not specified')
            return False

        if not os.path.isdir(archivedir):
            print("Archivedir '%s' does not exist or is not a directory" %
                  (archivedir))
            return False

        return True

    def examine(self, suspect):
        archiverules = self.config.get(self.section, 'archiverules')
        if archiverules == None or archiverules == "":
            return DUNNO

        if not os.path.exists(archiverules):
            self.logger.error(
                'Archive Rules file does not exist : %s' % archiverules)
            return DUNNO

        if self.filter == None:
            self.filter = SuspectFilter(archiverules)

        (match, arg) = self.filter.matches(suspect)
        if match:
            if arg != None and arg.lower() == 'no':
                suspect.debug("Suspect matches archive exception rule")
                self.logger.debug(
                    """Header matches archive exception rule - not archiving""")
            else:
                if arg != None and arg.lower() != 'yes':
                    self.logger.warning(
                        "Unknown archive action '%s' assuming 'yes'" % arg)
                self.logger.debug("""Header matches archive rule""")
                if suspect.get_tag('debug'):
                    suspect.debug(
                        "Suspect matches archiving rule (i would  archive it if we weren't in debug mode)")
                else:
                    self.archive(suspect)
        else:
            suspect.debug(
                "No archive rule/exception rule applies to this message")

    def archive(self, suspect):
        archivedir = self.config.get(self.section, 'archivedir')
        if archivedir == "":
            self.logger.error('Archivedir is not specified')
            return

        subdirtemplate = self.config.get(self.section, 'subdirtemplate')

        if self.config.has_option(self.section, 'makedomainsubdir') and subdirtemplate == self.requiredvars['subdirtemplate']['default']:
            self.logger.warning(
                "Archive config is using deprecated 'makedomainsubdir' config option. Emulating old behaviour. Update your config(subdirtemplate)")
            if self.config.getboolean(self.section, 'makedomainsubdir'):
                subdirtemplate = "${to_domain}"
            else:
                subdirtemplate = ""

        # the archive root dir
        startdir = os.path.abspath(archivedir)

        # relative dir within archive root
        subdir = apply_template(subdirtemplate, suspect)
        if subdir.endswith('/'):
            subdir = subdir[:-1]

        # filename without dir
        filenametemplate = self.config.get(self.section, 'filenametemplate')
        filename = apply_template(filenametemplate, suspect)
        # make sure filename can't create new folders
        filename = filename.replace('/', '_')

        # full relative filepath within archive dir
        fpath = "%s/%s" % (subdir, filename)

        # absolute final filepath
        requested_path = os.path.abspath("%s/%s" % (startdir, fpath))

        if not os.path.commonprefix([requested_path, startdir]).startswith(startdir):
            self.logger.error(
                "file path '%s' seems to be outside archivedir '%s' - storing to archivedir" % (requested_path, startdir))
            requested_path = "%s/%s" % (startdir, filename)

        finaldir = os.path.dirname(requested_path)
        if not os.path.isdir(finaldir):
            os.makedirs(finaldir, 0o755)

        if self.config.getboolean(self.section, 'storeoriginal'):
            shutil.copy(suspect.tempfile, requested_path)
        else:
            fp = open(requested_path, 'w')
            fp.write(suspect.get_source())
            fp.close()

        chmod = self.config.get(self.section, 'chmod')
        chgrp = self.config.get(self.section, 'chgrp')
        chown = self.config.get(self.section, 'chown')
        if chmod or chgrp or chown:
            self.setperms(requested_path, chmod, chgrp, chown)

        self.logger.info('Message from %s to %s archived as %s' % (
            suspect.from_address, suspect.to_address, requested_path))
        return requested_path

    def setperms(self, filename, chmod, chgrp, chown):
        """Set file permissions and ownership
        :param filename The target file
        :param chmod string representing the permissions (example '640')
        :param chgrp groupname or group id of the target group. the user running fuglu must be a member of this group for this to work
        :param chown username or user id of the target user. fuglu must run as root for this to work (which is not recommended for security reasons)
        """

        # chmod
        if chmod:
            perm = int(chmod, 8)
            try:
                os.chmod(filename, perm)
            except:
                self.logger.error(
                    'could not set permission on file %s' % filename)

        # chgrp
        changetogroup = -1
        if chgrp:
            group = None
            try:
                group = grp.getgrnam(chgrp)
            except KeyError:
                pass

            try:
                group = grp.getgrgid(int(chgrp))
            except KeyError:
                pass
            except ValueError:
                pass

            if group != None:
                changetogroup = group.gr_gid
            else:
                self.logger.warn("Group %s not found" % chgrp)

        # chown
        changetouser = -1
        if chown:
            user = None
            try:
                user = pwd.getpwnam(chown)
            except KeyError:
                pass

            try:
                user = pwd.getpwuid(int(chown))
            except KeyError:
                pass
            except ValueError:
                pass

            if user != None:
                changetouser = user.pw_uid
            else:
                self.logger.warn("User %s not found" % chown)

        if changetogroup != -1 or changetouser != -1:
            try:
                os.chown(filename, changetouser, changetogroup)
            except Exception as e:
                self.logger.error(
                    "Could not change user/group of file %s : %s" % (filename, str(e)))
