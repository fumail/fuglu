Test environment for bug #17
https://github.com/gryphius/fuglu/issues/17

For stress testing we use postfix's smtp-source
(tried xstress: compilation errors due to missing include, ctrl-c crashes my desktop...?)

bug reproducible in docker!





2015-03-06 07:36:02,383 INFO MESSAGE DELETED: e66a9b9a74f743869e9a2bb90154ab71
*** glibc detected *** /usr/bin/python: double free or corruption (fasttop): 0x00007fca40008ce0 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x76a16)[0x7fca49ee5a16]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x6c)[0x7fca49eea7bc]
/usr/lib/x86_64-linux-gnu/libmagic.so.1(file_reset+0x2e)[0x7fca47e9fdfe]
/usr/lib/x86_64-linux-gnu/libmagic.so.1(magic_buffer+0x21)[0x7fca47e95251]
/usr/lib/python2.7/lib-dynload/_ctypes.so(ffi_call_unix64+0x4c)[0x7fca48e4f834]
/usr/lib/python2.7/lib-dynload/_ctypes.so(ffi_call+0x3f1)[0x7fca48e4f2af]
/usr/lib/python2.7/lib-dynload/_ctypes.so(_ctypes_callproc+0x4d1)[0x7fca48e3cfd1]
/usr/lib/python2.7/lib-dynload/_ctypes.so(+0xd742)[0x7fca48e3d742]
/usr/bin/python(PyEval_EvalFrameEx+0x960)[0x4aab70]
/usr/bin/python(PyEval_EvalFrameEx+0xb00)[0x4aad10]
======= Memory map: ========
00400000-00657000 r-xp 00000000 00:10 9080                               /usr/bin/python2.7
00856000-00857000 r--p 00256000 00:10 9080                               /usr/bin/python2.7
00857000-008c0000 rw-p 00257000 00:10 9080                               /usr/bin/python2.7
008c0000-008d3000 rw-p 00000000 00:00 0
01442000-0180a000 rw-p 00000000 00:00 0                                  [heap]
7fca38000000-7fca38065000 rw-p 00000000 00:00 0
7fca38065000-7fca3c000000 ---p 00000000 00:00 0
7fca40000000-7fca40068000 rw-p 00000000 00:00 0
7fca40068000-7fca44000000 ---p 00000000 00:00 0
7fca44419000-7fca4445a000 rw-p 00000000 00:00 0
7fca4445a000-7fca4445b000 ---p 00000000 00:00 0
7fca4445b000-7fca44c5b000 rw-p 00000000 00:00 0                          [stack:18]
7fca44c5b000-7fca44c5c000 ---p 00000000 00:00 0
7fca44c5c000-7fca4545c000 rw-p 00000000 00:00 0                          [stack:17]
7fca4545c000-7fca4545d000 ---p 00000000 00:00 0
7fca4545d000-7fca45c5d000 rw-p 00000000 00:00 0                          [stack:16]
7fca45c5d000-7fca45c5e000 ---p 00000000 00:00 0
7fca45c5e000-7fca4645e000 rw-p 00000000 00:00 0                          [stack:15]
7fca4645e000-7fca4645f000 ---p 00000000 00:00 0
7fca4645f000-7fca46c5f000 rw-p 00000000 00:00 0                          [stack:14]
7fca46c5f000-7fca46c60000 ---p 00000000 00:00 0
7fca46c60000-7fca47460000 rw-p 00000000 00:00 0                          [stack:13]
7fca47460000-7fca47461000 ---p 00000000 00:00 0
7fca47461000-7fca47c61000 rw-p 00000000 00:00 0                          [stack:12]
7fca47c61000-7fca47e8e000 rw-p 00000000 00:10 8980                       /usr/share/file/magic.mgc
7fca47e8e000-7fca47ea9000 r-xp 00000000 00:10 8871                       /usr/lib/x86_64-linux-gnu/libmagic.so.1.0.0
7fca47ea9000-7fca480a8000 ---p 0001b000 00:10 8871                       /usr/lib/x86_64-linux-gnu/libmagic.so.1.0.0
7fca480a8000-7fca480a9000 r--p 0001a000 00:10 8871                       /usr/lib/x86_64-linux-gnu/libmagic.so.1.0.0
7fca480a9000-7fca480aa000 rw-p 0001b000 00:10 8871                       /usr/lib/x86_64-linux-gnu/libmagic.so.1.0.0
7fca480aa000-7fca480b5000 r-xp 00000000 00:10 729                        /lib/x86_64-linux-gnu/libnss_files-2.13.so
7fca480b5000-7fca482b4000 ---p 0000b000 00:10 729                        /lib/x86_64-linux-gnu/libnss_files-2.13.so
7fca482b4000-7fca482b5000 r--p 0000a000 00:10 729                        /lib/x86_64-linux-gnu/libnss_files-2.13.so
7fca482b5000-7fca482b6000 rw-p 0000b000 00:10 729                        /lib/x86_64-linux-gnu/libnss_files-2.13.so
7fca482b6000-7fca482c0000 r-xp 00000000 00:10 733                        /lib/x86_64-linux-gnu/libnss_nis-2.13.so
7fca482c0000-7fca484bf000 ---p 0000a000 00:10 733                        /lib/x86_64-linux-gnu/libnss_nis-2.13.so
7fca484bf000-7fca484c0000 r--p 00009000 00:10 733                        /lib/x86_64-linux-gnu/libnss_nis-2.13.so
7fca484c0000-7fca484c1000 rw-p 0000a000 00:10 733                        /lib/x86_64-linux-gnu/libnss_nis-2.13.so
7fca484c1000-7fca484d6000 r-xp 00000000 00:10 723                        /lib/x86_64-linux-gnu/libnsl-2.13.so
7fca484d6000-7fca486d5000 ---p 00015000 00:10 723                        /lib/x86_64-linux-gnu/libnsl-2.13.so
7fca486d5000-7fca486d6000 r--p 00014000 00:10 723                        /lib/x86_64-linux-gnu/libnsl-2.13.so
7fca486d6000-7fca486d7000 rw-p 00015000 00:10 723                        /lib/x86_64-linux-gnu/libnsl-2.13.so
7fca486d7000-7fca486d9000 rw-p 00000000 00:00 0
7fca486d9000-7fca486e0000 r-xp 00000000 00:10 725                        /lib/x86_64-linux-gnu/libnss_compat-2.13.so
7fca486e0000-7fca488df000 ---p 00007000 00:10 725                        /lib/x86_64-linux-gnu/libnss_compat-2.13.so
7fca488df000-7fca488e0000 r--p 00006000 00:10 725                        /lib/x86_64-linux-gnu/libnss_compat-2.13.so
7fca488e0000-7fca488e1000 rw-p 00007000 00:10 725                        /lib/x86_64-linux-gnu/libnss_compat-2.13.so
7fca488e1000-7fca48a26000 rw-p 00000000 00:00 0
7fca48a26000-7fca48a2a000 r-xp 00000000 00:10 767                        /lib/x86_64-linux-gnu/libuuid.so.1.3.0
7fca48a2a000-7fca48c29000 ---p 00004000 00:10 767                        /lib/x86_64-linux-gnu/libuuid.so.1.3.0
7fca48c29000-7fca48c2a000 r--p 00003000 00:10 767                        /lib/x86_64-linux-gnu/libuuid.so.1.3.0
7fca48c2a000-7fca48c2b000 rw-p 00004000 00:10 767                        /lib/x86_64-linux-gnu/libuuid.so.1.3.0
7fca48c2b000-7fca48c2e000 r-xp 00000000 00:10 7611                       /usr/lib/python2.7/lib-dynload/_hashlib.so
7fca48c2e000-7fca48e2e000 ---p 00003000 00:10 7611                       /usr/lib/python2.7/lib-dynload/_hashlib.so
7fca48e2e000-7fca48e2f000 r--p 00003000 00:10 7611                       /usr/lib/python2.7/lib-dynload/_hashlib.so
7fca48e2f000-7fca48e30000 rw-p 00004000 00:10 7611                       /usr/lib/python2.7/lib-dynload/_hashlib.so
7fca48e30000-7fca48e56000 r-xp 00000000 00:10 7619                       /usr/lib/python2.7/lib-dynload/_ctypes.so
7fca48e56000-7fca49055000 ---p 00026000 00:10 7619                       /usr/lib/python2.7/lib-dynload/_ctypes.so
7fca49055000-7fca49056000 r--p 00025000 00:10 7619                       /usr/lib/python2.7/lib-dynload/_ctypes.so
7fca49056000-7fca4905a000 rw-p 00026000 00:10 7619                       /usr/lib/python2.7/lib-dynload/_ctypes.so
7fca4905a000-7fca4919e000 rw-p 00000000 00:00 0
7fca4919e000-7fca491b2000 r-xp 00000000 00:10 7609                       /usr/lib/python2.7/lib-dynload/datetime.so
7fca491b2000-7fca493b2000 ---p 00014000 00:10 7609                       /usr/lib/python2.7/lib-dynload/datetime.so
7fca493b2000-7fca493b3000 r--p 00014000 00:10 7609                       /usr/lib/python2.7/lib-dynload/datetime.so
7fca493b3000-7fca493b7000 rw-p 00015000 00:10 7609                       /usr/lib/python2.7/lib-dynload/datetime.so
7fca493b7000-7fca493f8000 rw-p 00000000 00:00 0
7fca493f8000-7fca495c2000 r-xp 00000000 00:10 8872                       /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0
7fca495c2000-7fca497c2000 ---p 001ca000 00:10 8872                       /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0
7fca497c2000-7fca497dd000 r--p 001ca000 00:10 8872                       /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0
7fca497dd000-7fca497ec000 rw-p 001e5000 00:10 8872                       /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0
7fca497ec000-7fca497f0000 rw-p 00000000 00:00 0
7fca497f0000-7fca49846000 r-xp 00000000 00:10 8875                       /usr/lib/x86_64-linux-gnu/libssl.so.1.0.0
7fca49846000-7fca49a46000 ---p 00056000 00:10 8875                       /usr/lib/x86_64-linux-gnu/libssl.so.1.0.0
7fca49a46000-7fca49a49000 r--p 00056000 00:10 8875                       /usr/lib/x86_64-linux-gnu/libssl.so.1.0.0
7fca49a49000-7fca49a50000 rw-p 00059000 00:10 8875                       /usr/lib/x86_64-linux-gnu/libssl.so.1.0.0
7fca49a50000-7fca49a58000 r-xp 00000000 00:10 7603                       /usr/lib/python2.7/lib-dynload/_ssl.so
7fca49a58000-7fca49c57000 ---p 00008000 00:10 7603                       /usr/lib/python2.7/lib-dynload/_ssl.so
7fca49c57000-7fca49c58000 r--p 00007000 00:10 7603                       /usr/lib/python2.7/lib-dynload/_ssl.so
7fca49c58000-7fca49c59000 rw-p 00008000 00:10 7603                       /usr/lib/python2.7/lib-dynload/_ssl.so
7fca49c59000-7fca49c6e000 r-xp 00000000 00:10 711                        /lib/x86_64-linux-gnu/libgcc_s.so.1
7fca49c6e000-7fca49e6e000 ---p 00015000 00:10 711                        /lib/x86_64-linux-gnu/libgcc_s.so.1
7fca49e6e000-7fca49e6f000 rw-p 00015000 00:10 711                        /lib/x86_64-linux-gnu/libgcc_s.so.1
7fca49e6f000-7fca49ff1000 r-xp 00000000 00:10 697                        /lib/x86_64-linux-gnu/libc-2.13.so
7fca49ff1000-7fca4a1f1000 ---p 00182000 00:10 697                        /lib/x86_64-linux-gnu/libc-2.13.so
7fca4a1f1000-7fca4a1f5000 r--p 00182000 00:10 697                        /lib/x86_64-linux-gnu/libc-2.13.so
7fca4a1f5000-7fca4a1f6000 rw-p 00186000 00:10 697                        /lib/x86_64-linux-gnu/libc-2.13.so
7fca4a1f6000-7fca4a1fb000 rw-p 00000000 00:00 0
7fca4a1fb000-7fca4a27c000 r-xp 00000000 00:10 716                        /lib/x86_64-linux-gnu/libm-2.13.so
7fca4a27c000-7fca4a47b000 ---p 00081000 00:10 716                        /lib/x86_64-linux-gnu/libm-2.13.so
7fca4a47b000-7fca4a47c000 r--p 00080000 00:10 716                        /lib/x86_64-linux-gnu/libm-2.13.so
7fca4a47c000-7fca4a47d000 rw-p 00081000 00:10 716                        /lib/x86_64-linux-gnu/libm-2.13.so
7fca4a47d000-7fca4a493000 r-xp 00000000 00:10 769                        /lib/x86_64-linux-gnu/libz.so.1.2.7
7fca4a493000-7fca4a692000 ---p 00016000 00:10 769                        /lib/x86_64-linux-gnu/libz.so.1.2.7
7fca4a692000-7fca4a693000 r--p 00015000 00:10 769                        /lib/x86_64-linux-gnu/libz.so.1.2.7
7fca4a693000-7fca4a694000 rw-p 00016000 00:10 769                        /lib/x86_64-linux-gnu/libz.so.1.2.7
7fca4a694000-7fca4a696000 r-xp 00000000 00:10 764                        /lib/x86_64-linux-gnu/libutil-2.13.so
7fca4a696000-7fca4a895000 ---p 00002000 00:10 764                        /lib/x86_64-linux-gnu/libutil-2.13.so
7fca4a895000-7fca4a896000 r--p 00001000 00:10 764                        /lib/x86_64-linux-gnu/libutil-2.13.so
7fca4a896000-7fca4a897000 rw-p 00002000 00:10 764                        /lib/x86_64-linux-gnu/libutil-2.13.so
7fca4a897000-7fca4a899000 r-xp 00000000 00:10 705                        /lib/x86_64-linux-gnu/libdl-2.13.so
7fca4a899000-7fca4aa99000 ---p 00002000 00:10 705                        /lib/x86_64-linux-gnu/libdl-2.13.so
7fca4aa99000-7fca4aa9a000 r--p 00002000 00:10 705                        /lib/x86_64-linux-gnu/libdl-2.13.so
7fca4aa9a000-7fca4aa9b000 rw-p 00003000 00:10 705                        /lib/x86_64-linux-gnu/libdl-2.13.so
7fca4aa9b000-7fca4aab2000 r-xp 00000000 00:10 744                        /lib/x86_64-linux-gnu/libpthread-2.13.so
7fca4aab2000-7fca4acb1000 ---p 00017000 00:10 744                        /lib/x86_64-linux-gnu/libpthread-2.13.so
7fca4acb1000-7fca4acb2000 r--p 00016000 00:10 744                        /lib/x86_64-linux-gnu/libpthread-2.13.so
7fca4acb2000-7fca4acb3000 rw-p 00017000 00:10 744                        /lib/x86_64-linux-gnu/libpthread-2.13.so
7fca4acb3000-7fca4acb7000 rw-p 00000000 00:00 0
7fca4acb7000-7fca4acd7000 r-xp 00000000 00:10 681                        /lib/x86_64-linux-gnu/ld-2.13.so
7fca4ad16000-7fca4ae1a000 rw-p 00000000 00:00 0
7fca4ae4b000-7fca4aed3000 rw-p 00000000 00:00 0
7fca4aed3000-7fca4aed4000 rwxp 00000000 00:00 0
7fca4aed4000-7fca4aed6000 rw-p 00000000 00:00 0
7fca4aed6000-7fca4aed7000 r--p 0001f000 00:10 681                        /lib/x86_64-linux-gnu/ld-2.13.so
7fca4aed7000-7fca4aed8000 rw-p 00020000 00:10 681                        /lib/x86_64-linux-gnu/ld-2.13.so
7fca4aed8000-7fca4aed9000 rw-p 00000000 00:00 0
7fffdc1b8000-7fffdc1d9000 rw-p 00000000 00:00 0                          [stack]
7fffdc1e6000-7fffdc1e8000 r--p 00000000 00:00 0                          [vvar]
7fffdc1e8000-7fffdc1ea000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
