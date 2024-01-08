#! /bin/env python

import toolspath
from testing import Xv6Build, Xv6Test

class test1(Xv6Test):
   name = "test_1"
   description = "Simple mmap with MAP_ANON | MAP_FIXED"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test2(Xv6Test):
   name = "test_2"
   description = "Simple mmap/munmap with MAP_ANON | MAP_FIXED"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test3(Xv6Test):
   name = "test_3"
   description = "Access the mmap memory allocated with MAP_ANON | MAP_FIXED, then munmap"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test4(Xv6Test):
   name = "test_4"
   description = "Try mmap MAP_ANON without MAP_FIXED"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test5(Xv6Test):
   name = "test_5"
   description = "Try to allocate memory with MAP_FIXED at an illegal address"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test6(Xv6Test):
   name = "test_6"
   description = "mmap a file"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test7(Xv6Test):
   name = "test_7"
   description = "Changes to the mmapped memory should be reflected in file after munmap"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test8(Xv6Test):
   name = "test_8"
   description = "MAP_GROWSUP that adds a single page to anonymous mapping"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test9(Xv6Test):
   name = "test_9"
   description = "MAP_GROWSUP with file-backed mapping"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test10(Xv6Test):
   name = "test_10"
   description = "Try growing memory without MAP_GROWSUP - should segfault"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   success_pattern = "Segmentation Fault"

class test11(Xv6Test):
   name = "test_11"
   description = "Two MAP_GROWSUP mappings with a single guard page in between - the lower should not extend"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   success_pattern = "Segmentation Fault"

class test12(Xv6Test):
   name = "test_12"
   description = "Child access to parent mmap"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test13(Xv6Test):
   name = "test_13"
   description = "Changes made to mmapped memory should not be reflected in file when MAP_PRIVATE is set"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test14(Xv6Test):
   name = "test_14"
   description = "Child should access file data with MAP_PRIVATE flag"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'

class test15(Xv6Test):
   name = "test_15"
   description = "Parent should not see child mofications to memory with MAP_PRIVATE"
   tester = "ctests/" + name + ".c"
   make_qemu_args = "CPUS=1"
   point_value = 1
   failure_pattern = 'Segmentation Fault'


import toolspath
from testing.runtests import main
main(Xv6Build, all_tests=[test1, test2, test3, test4, test5, test6, test7, test8, test9, test10, test11, test12, test13, test14, test15])
