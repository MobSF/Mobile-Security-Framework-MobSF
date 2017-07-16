This directory contains prebuilt binaries used by Telemetry which allow it to
be run without requiring any compilation.

For usage instructions, see:
http://www.chromium.org/developers/telemetry/upload_to_cloud_storage

avconv:
   version 0.8.9-4:0.8.9-0ubuntu0.12.04.1

IEDriverServer binary:
  Both 32-bit and 64-bit are of version 2.35.2.

ipfw and ipfw_mod.ko:
  Version 20120812

perfhost_trusty:
  Built from branch modified by vmiura on github. The git branch used is
  "perf_tracing_changes" but in the directions below I have included the actual
  hash of the checkout.

  Make sure you have the proper libraries installed for symbol demangling:
    shell> sudo apt-get install binutils-dev
    shell> sudo apt-get install libiberty-dev

  Directions for building perf:
    shell> git clone https://github.com/vmiura/linux.git
    shell> cd linux
    shell> git checkout e1fe871e4a33712ad4964a70904d5d59188e3cc2
    shell> cd tools/perf
    shell> make
    shell> ./perf test
    Tests should mostly pass, except a few:
     1: vmlinux symtab matches kallsyms                        : FAILED!
     2: detect open syscall event                              : FAILED!
     3: detect open syscall event on all cpus                  : FAILED!
     4: read samples using the mmap interface                  : FAILED!
     5: parse events tests                                     : FAILED!
     [snip]
     11: Check parsing of sched tracepoints fields              : FAILED!
     12: Generate and check syscalls:sys_enter_open event fields: FAILED!
     21: Test object code reading          :[kernel.kallsyms] ... FAILED!
    shell> mv perf perfhost_trusty

android/armeabi-v7a/perf:
  Follow http://source.android.com/source/building.html
  . build/envsetup.sh
  lunch aosp_arm-user

2013-09-26 - bulach - perf / perfhost / tcpdump:
  git revert -n 93501d3 # issue with __strncpy_chk2
  make -j32 perf perfhost tcpdump

android/arm64-v8a/perf:
  Same as above, with aarch64 architecture, from branch android-5.0.0_r2
