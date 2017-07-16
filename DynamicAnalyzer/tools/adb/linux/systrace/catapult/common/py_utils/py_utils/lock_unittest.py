# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import multiprocessing
import os
import time
import unittest
import tempfile


from py_utils import lock


def _AppendTextToFile(file_name):
  with open(file_name, 'a') as f:
    lock.AcquireFileLock(f, lock.LOCK_EX)
    # Sleep 100 ms to increase the chance of another process trying to acquire
    # the lock of file as the same time.
    time.sleep(0.1)
    f.write('Start')
    for _ in range(10000):
      f.write('*')
    f.write('End')


def _ReadFileWithSharedLockBlockingThenWrite(read_file, write_file):
  with open(read_file, 'r') as f:
    lock.AcquireFileLock(f, lock.LOCK_SH)
    content = f.read()
    with open(write_file, 'a') as f2:
      lock.AcquireFileLock(f2, lock.LOCK_EX)
      f2.write(content)


def _ReadFileWithExclusiveLockNonBlocking(target_file, status_file):
  with open(target_file, 'r') as f:
    try:
      lock.AcquireFileLock(f, lock.LOCK_EX | lock.LOCK_NB)
      with open(status_file, 'w') as f2:
        f2.write('LockException was not raised')
    except lock.LockException:
      with open(status_file, 'w') as f2:
        f2.write('LockException raised')


class FileLockTest(unittest.TestCase):
  def setUp(self):
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.close()
    self.temp_file_path = tf.name

  def tearDown(self):
    os.remove(self.temp_file_path)

  def testExclusiveLock(self):
    processess = []
    for _ in range(10):
      p = multiprocessing.Process(
          target=_AppendTextToFile, args=(self.temp_file_path,))
      p.start()
      processess.append(p)
    for p in processess:
      p.join()

    # If the file lock works as expected, there should be 10 atomic writes of
    # 'Start***...***End' to the file in some order, which lead to the final
    # file content as below.
    expected_file_content = ''.join((['Start'] + ['*']*10000 + ['End']) * 10)
    with open(self.temp_file_path, 'r') as f:
      # Use assertTrue instead of assertEquals since the strings are big, hence
      # assertEquals's assertion failure will contain huge strings.
      self.assertTrue(expected_file_content == f.read())

  def testSharedLock(self):
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.close()
    temp_write_file = tf.name
    try:
      with open(self.temp_file_path, 'w') as f:
        f.write('0123456789')
      with open(self.temp_file_path, 'r') as f:
        # First, acquire a shared lock on temp_file_path
        lock.AcquireFileLock(f, lock.LOCK_SH)

        processess = []
        # Create 10 processes that also try to acquire shared lock from
        # temp_file_path then append temp_file_path's content to temp_write_file
        for _ in range(10):
          p = multiprocessing.Process(
              target=_ReadFileWithSharedLockBlockingThenWrite,
              args=(self.temp_file_path, temp_write_file))
          p.start()
          processess.append(p)
        for p in processess:
          p.join()

      # temp_write_file should contains 10 copy of temp_file_path's content.
      with open(temp_write_file, 'r') as f:
        self.assertEquals('0123456789'*10, f.read())
    finally:
      os.remove(temp_write_file)

  def testNonBlockingLockAcquiring(self):
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.close()
    temp_status_file = tf.name
    try:
      with open(self.temp_file_path, 'w') as f:
        lock.AcquireFileLock(f, lock.LOCK_EX)
        p = multiprocessing.Process(
            target=_ReadFileWithExclusiveLockNonBlocking,
            args=(self.temp_file_path, temp_status_file))
        p.start()
        p.join()
      with open(temp_status_file, 'r') as f:
        self.assertEquals('LockException raised', f.read())
    finally:
      os.remove(temp_status_file)

  def testUnlockBeforeClosingFile(self):
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.close()
    temp_status_file = tf.name
    try:
      with open(self.temp_file_path, 'r') as f:
        lock.AcquireFileLock(f, lock.LOCK_SH)
        lock.ReleaseFileLock(f)
        p = multiprocessing.Process(
            target=_ReadFileWithExclusiveLockNonBlocking,
            args=(self.temp_file_path, temp_status_file))
        p.start()
        p.join()
      with open(temp_status_file, 'r') as f:
        self.assertEquals('LockException was not raised', f.read())
    finally:
      os.remove(temp_status_file)

  def testContextualLock(self):
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.close()
    temp_status_file = tf.name
    try:
      with open(self.temp_file_path, 'r') as f:
        with lock.FileLock(f, lock.LOCK_EX):
          # Within this block, accessing self.temp_file_path from another
          # process should raise exception.
          p = multiprocessing.Process(
              target=_ReadFileWithExclusiveLockNonBlocking,
              args=(self.temp_file_path, temp_status_file))
          p.start()
          p.join()
          with open(temp_status_file, 'r') as f:
            self.assertEquals('LockException raised', f.read())

        # Accessing self.temp_file_path here should not raise exception.
        p = multiprocessing.Process(
            target=_ReadFileWithExclusiveLockNonBlocking,
            args=(self.temp_file_path, temp_status_file))
        p.start()
        p.join()
      with open(temp_status_file, 'r') as f:
        self.assertEquals('LockException was not raised', f.read())
    finally:
      os.remove(temp_status_file)
