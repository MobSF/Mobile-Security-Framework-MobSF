# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from telemetry.timeline import memory_dump_event
import mock


def MakeRawMemoryDumpEvent(dump_id='123456ABCDEF', pid=1234, start=0,
                           mmaps=None, allocators=None):

  def vm_region(mapped_file, byte_stats):
    return {
      'mf': mapped_file,
      'bs': {k: hex(v) for k, v in byte_stats.iteritems()}}

  def attrs(sizes):
    return {'attrs': {k: {'value': hex(v), 'units': 'bytes'}
                      for k, v in sizes.iteritems()}}

  if allocators is None:
    allocators = {}

  event = {'ph': 'v', 'id': dump_id, 'pid': pid, 'ts': start * 1000,
           'args': {'dumps': {'allocators': {
               name: attrs(sizes) for name, sizes in allocators.iteritems()}}}}
  if mmaps:
    event['args']['dumps']['process_mmaps'] = {
      'vm_regions': [vm_region(mapped_file, byte_stats)
                     for mapped_file, byte_stats in mmaps.iteritems()]}

  return event


def TestProcessDumpEvent(dump_id='123456ABCDEF', pid=1234, start=0, mmaps=None,
                         allocators=None):
  event = MakeRawMemoryDumpEvent(dump_id, pid, start, mmaps=mmaps,
                                allocators=allocators)
  process = mock.Mock()
  process.pid = event['pid']
  return memory_dump_event.ProcessMemoryDumpEvent(process, [event])


class ProcessMemoryDumpEventUnitTest(unittest.TestCase):

  def testProcessMemoryDump_allocators(self):
    process = mock.Mock()
    process.pid = 1234
    events = [
      MakeRawMemoryDumpEvent(
        pid=process.pid, allocators={
          'v8': {'size': 10, 'allocated_objects_size': 5},
          'v8/allocated_objects': {'size': 4},
          'skia': {'not_size': 10,
          'allocated_objects_size': 5},
          'skia/cache1': {'size': 24}
        }
      ),
      MakeRawMemoryDumpEvent(
        pid=process.pid, allocators={
          'skia/cache2': {'not_size': 20},
          'skia/cache2/obj1': {'size': 8},
          'skia/cache2/obj2': {'size': 9},
          'skia_different/obj': {'size': 30},
          'skia_different/obj/not_counted': {'size': 26},
          'global/0xdead': {'size': 26}
        }
      )
    ]
    memory_dump = memory_dump_event.ProcessMemoryDumpEvent(process, events)

    EXPECTED_ALLOCATORS = {
      'skia': {
        'allocated_objects_size': 5,
        'not_size': 30,
        'size': 41
      },
      'v8': {
        'allocated_objects_size': 5,
        'size': 10
      },
      'skia_different': {'size': 30}
    }

    self.assertEquals(memory_dump._allocators, EXPECTED_ALLOCATORS)

  def testProcessMemoryDump_mmaps(self):
    ALL = [2 ** x for x in range(8)]
    (JAVA_SPACES, JAVA_CACHE, ASHMEM, NATIVE_1, NATIVE_2, STACK, FILES_APK,
     DEVICE_GPU) = ALL

    memory_dump = TestProcessDumpEvent(mmaps={
      '/dev/ashmem/dalvik-space-foo': {'pss': JAVA_SPACES},
      '/dev/ashmem/dalvik-jit-code-cache': {'pss': JAVA_CACHE},
      '/dev/ashmem/other-random-stuff': {'pss': ASHMEM},
      '[heap] bar': {'pss': NATIVE_1},
      '': {'pss': NATIVE_2},
      '[stack thingy]': {'pss': STACK},
      'my_little_app.apk': {'pss': FILES_APK},
      '/dev/mali': {'pss': DEVICE_GPU}
    })

    EXPECTED = {
      '/': sum(ALL),
      '/Android/Java runtime': JAVA_SPACES + JAVA_CACHE,
      '/Android/Ashmem': ASHMEM,
      '/Android': JAVA_SPACES + JAVA_CACHE + ASHMEM,
      '/Native heap': NATIVE_1 + NATIVE_2,
      '/Stack': STACK,
      '/Files/apk': FILES_APK,
      '/Devices': DEVICE_GPU}

    self.assertTrue(memory_dump.has_mmaps)
    for path, value in EXPECTED.iteritems():
      self.assertEquals(
          value,
          memory_dump.GetMemoryBucket(path).GetValue('proportional_resident'))

  def testProcessMemoryDump_composability(self):
    java_spaces = 100
    process = mock.Mock()
    process.pid = 1234
    allocators = {'v8': {'size': 10}}
    mmaps = {'/dev/ashmem/dalvik-space-foo': {'pss': java_spaces}}

    events = [MakeRawMemoryDumpEvent(pid=process.pid, allocators=allocators),
              MakeRawMemoryDumpEvent(pid=process.pid, mmaps=mmaps)]
    memory_dump = memory_dump_event.ProcessMemoryDumpEvent(process, events)

    self.assertEquals(memory_dump._allocators, allocators)

    EXPECTED_MMAPS = {
      '/': java_spaces,
      '/Android/Java runtime': java_spaces,
      '/Android': java_spaces,
    }

    self.assertTrue(memory_dump.has_mmaps)
    for path, value in EXPECTED_MMAPS.iteritems():
      self.assertEquals(value,
          memory_dump.GetMemoryBucket(path).GetValue('proportional_resident'))


class MemoryDumpEventUnitTest(unittest.TestCase):
  def testRepr(self):
    process_dump1 = TestProcessDumpEvent(
        mmaps={'/dev/ashmem/other-ashmem': {'pss': 5}},
        allocators={'v8': {'size': 10, 'allocated_objects_size' : 5}})
    process_dump2 = TestProcessDumpEvent(
        mmaps={'/dev/ashmem/libc malloc': {'pss': 42, 'pd': 27}},
        allocators={'v8': {'size': 20, 'allocated_objects_size' : 10},
                    'oilpan': {'size': 40}})
    global_dump = memory_dump_event.GlobalMemoryDump(
        [process_dump1, process_dump2])

    self.assertEquals(
        repr(process_dump1),
        'ProcessMemoryDumpEvent[pid=1234, allocated_objects_v8=5,'
        ' allocator_v8=10, mmaps_ashmem=5, mmaps_java_heap=0,'
        ' mmaps_native_heap=0, mmaps_overall_pss=5, mmaps_private_dirty=0]')
    self.assertEquals(
        repr(process_dump2),
        'ProcessMemoryDumpEvent[pid=1234, allocated_objects_v8=10,'
        ' allocator_oilpan=40, allocator_v8=20, mmaps_ashmem=0,'
        ' mmaps_java_heap=0, mmaps_native_heap=42, mmaps_overall_pss=42,'
        ' mmaps_private_dirty=27]')
    self.assertEquals(
        repr(global_dump),
        'GlobalMemoryDump[id=123456ABCDEF, allocated_objects_v8=15,'
        ' allocator_oilpan=40, allocator_v8=30, mmaps_ashmem=5,'
        ' mmaps_java_heap=0, mmaps_native_heap=42, mmaps_overall_pss=47,'
        ' mmaps_private_dirty=27]')

  def testDumpEventsTiming(self):
    process = mock.Mock()
    process.pid = 1
    composable_dump = memory_dump_event.ProcessMemoryDumpEvent(
        process,
        [
          MakeRawMemoryDumpEvent(pid=process.pid, start=8),
          MakeRawMemoryDumpEvent(pid=process.pid, start=16),
          MakeRawMemoryDumpEvent(pid=process.pid, start=10)
        ])
    self.assertAlmostEquals(8.0, composable_dump.start)
    self.assertAlmostEquals(16.0, composable_dump.end)

    memory_dump = memory_dump_event.GlobalMemoryDump([
        composable_dump,
        TestProcessDumpEvent(pid=3, start=8),
        TestProcessDumpEvent(pid=2, start=13),
        TestProcessDumpEvent(pid=4, start=7)])

    self.assertFalse(memory_dump.has_mmaps)
    self.assertEquals(4, len(list(memory_dump.IterProcessMemoryDumps())))
    self.assertItemsEqual([1, 2, 3, 4], memory_dump.pids)
    self.assertAlmostEquals(7.0, memory_dump.start)
    self.assertAlmostEquals(16.0, memory_dump.end)
    self.assertAlmostEquals(9.0, memory_dump.duration)

  def testGetMemoryUsage(self):
    ALL = [2 ** x for x in range(7)]
    (JAVA_HEAP_1, JAVA_HEAP_2, ASHMEM_1, ASHMEM_2, NATIVE,
     DIRTY_1, DIRTY_2) = ALL

    memory_dump = memory_dump_event.GlobalMemoryDump([
        TestProcessDumpEvent(pid=1, mmaps={
            '/dev/ashmem/dalvik-alloc space': {'pss': JAVA_HEAP_1}}),
        TestProcessDumpEvent(pid=2, mmaps={
            '/dev/ashmem/other-ashmem': {'pss': ASHMEM_1, 'pd': DIRTY_1}}),
        TestProcessDumpEvent(pid=3, mmaps={
            '[heap] native': {'pss': NATIVE, 'pd': DIRTY_2},
            '/dev/ashmem/dalvik-zygote space': {'pss': JAVA_HEAP_2}}),
        TestProcessDumpEvent(pid=4, mmaps={
            '/dev/ashmem/other-ashmem': {'pss': ASHMEM_2}})])

    self.assertTrue(memory_dump.has_mmaps)
    self.assertItemsEqual([1, 2, 3, 4], memory_dump.pids)
    self.assertEquals({'mmaps_overall_pss': sum(ALL[:5]),
                       'mmaps_private_dirty': DIRTY_1 + DIRTY_2,
                       'mmaps_java_heap': JAVA_HEAP_1 + JAVA_HEAP_2,
                       'mmaps_ashmem': ASHMEM_1 + ASHMEM_2,
                       'mmaps_native_heap': NATIVE},
                      memory_dump.GetMemoryUsage())

  def testGetMemoryUsageWithAllocators(self):
    process_dump1 = TestProcessDumpEvent(
        mmaps={'/dev/ashmem/other-ashmem': {'pss': 5}},
        allocators={'v8': {'size': 10, 'allocated_objects_size' : 5}})
    process_dump2 = TestProcessDumpEvent(
        mmaps={'/dev/ashmem/other-ashmem': {'pss': 5}},
        allocators={'v8': {'size': 20, 'allocated_objects_size' : 10}})
    memory_dump = memory_dump_event.GlobalMemoryDump(
        [process_dump1, process_dump2])
    self.assertEquals({'mmaps_overall_pss': 10,
                       'mmaps_private_dirty': 0,
                       'mmaps_java_heap': 0,
                       'mmaps_ashmem': 10,
                       'mmaps_native_heap': 0,
                       'allocator_v8': 30,
                       'allocated_objects_v8': 15},
                      memory_dump.GetMemoryUsage())

  def testGetMemoryUsageWithAndroidMemtrack(self):
    GL1, EGL1, GL2, EGL2 = [2 ** x for x in range(4)]
    process_dump1 = TestProcessDumpEvent(
        allocators={'gpu/android_memtrack/gl': {'memtrack_pss' : GL1},
                    'gpu/android_memtrack/graphics': {'memtrack_pss': EGL1}})
    process_dump2 = TestProcessDumpEvent(
        allocators={'gpu/android_memtrack/gl': {'memtrack_pss' : GL2},
                    'gpu/android_memtrack/graphics': {'memtrack_pss': EGL2}})
    memory_dump = memory_dump_event.GlobalMemoryDump(
        [process_dump1, process_dump2])
    self.assertEquals({'android_memtrack_gl': GL1 + GL2,
                       'android_memtrack_graphics': EGL1 + EGL2},
                      memory_dump.GetMemoryUsage())

  def testGetMemoryUsageDiscountsTracing(self):
    ALL = [2 ** x for x in range(5)]
    (HEAP, DIRTY, MALLOC, TRACING_1, TRACING_2) = ALL

    memory_dump = memory_dump_event.GlobalMemoryDump([
        TestProcessDumpEvent(
            mmaps={'/dev/ashmem/libc malloc': {'pss': HEAP + TRACING_2,
                                               'pd': DIRTY + TRACING_2}},
            allocators={
                'tracing': {'size': TRACING_1, 'resident_size': TRACING_2},
                'malloc': {'size': MALLOC + TRACING_1}})])

    self.assertEquals({'mmaps_overall_pss': HEAP,
                       'mmaps_private_dirty': DIRTY,
                       'mmaps_java_heap': 0,
                       'mmaps_ashmem': 0,
                       'mmaps_native_heap': HEAP,
                       'allocator_tracing': TRACING_1,
                       'allocator_malloc': MALLOC},
                      memory_dump.GetMemoryUsage())
