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
#
import os
import pwd
import grp
import atexit


class DaemonStuff(object):

    """Makes a daemon out of a python program"""

    def __init__(self, pidfilename):
        self.pidfile = pidfilename

    def delpid(self):
        """Delete the pid file"""
        try:
            os.remove(self.pidfile)
        except:
            pass

    def createDaemon(self):
        """Detach a process from the controlling terminal and run it in the
        background as a daemon.
        Example from: http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/278731
        """

        try:
            pid = os.fork()
        except OSError as e:
            raise Exception("%s [%d]" % (e.strerror, e.errno))

        if (pid == 0):
            os.setsid()
            try:
                pid = os.fork()    # Fork a second child.
            except OSError as e:
                raise Exception("%s [%d]" % (e.strerror, e.errno))

            if (pid == 0):    # The second child.
                os.chdir('/')
                os.umask(0)
            else:
                # exit() or _exit()?  See below.
                # Exit parent (the first child) of the second child.
                os._exit(0)
        else:
            os._exit(0)    # Exit parent of the first child.

        import resource        # Resource usage information.
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if (maxfd == resource.RLIM_INFINITY):
            maxfd = 1024

        # Iterate through and close all file descriptors.
        for fd in range(0, maxfd):
            try:
                os.close(fd)
            except OSError:    # ERROR, fd wasn't open to begin with (ignored)
                pass
        os.open('/dev/null', os.O_RDWR)    # standard input (0)

        # Duplicate standard input to standard output and standard error.
        os.dup2(0, 1)            # standard output (1)
        os.dup2(0, 2)            # standard error (2)

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        pidfd = os.open(self.pidfile, os.O_WRONLY | os.O_CREAT, 0o644)
        os.write(pidfd, "%s\n" % pid)
        os.close(pidfd)
        return(0)

    def drop_privs(self, username='nobody', groupname='nobody', keep_supplemental_groups=True):
        """Drop privileges of the current process to specified unprivileged user and group. If keep_supplemental_groups is True,
        the process will also be associated with all groups the unprivileged user belongs to.
        """
        try:
            running_uid = pwd.getpwnam(username).pw_uid
            running_gid = grp.getgrnam(groupname).gr_gid
        except:
            raise Exception('Can not drop privileges, user %s or group %s does not exist' % (
                username, groupname))
        new_umask = 0o077
        os.umask(new_umask)

        os.setgid(running_gid)
        if keep_supplemental_groups:
            os.setgroups(self._get_group_ids(username))
        os.setuid(running_uid)

    def _get_group_ids(self, username):
        """Return a list of group ids the user belongs to"""
        gids = [g.gr_gid for g in grp.getgrall() if username in g.gr_mem]
        gid = pwd.getpwnam(username).pw_gid
        gids.append(grp.getgrgid(gid).gr_gid)
        return [groupid for groupid in set(gids)]
