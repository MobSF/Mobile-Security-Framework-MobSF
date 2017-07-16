from modulegraph import zipio
import os
import time
import sys

if sys.version_info[:2] <= (2,6):
    import unittest2 as unittest

else:
    import unittest

TESTDATA=os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'testdata')

class TestModuleGraph (unittest.TestCase):
    def test_locating(self):
        # Private function
        self.assertEqual(zipio._locate('/usr/bin/ditto'), ('/usr/bin/ditto', None))
        self.assertEqual(zipio._locate('/usr/bin/ditto/bar'), ('/usr/bin/ditto', 'bar'))
        self.assertEqual(zipio._locate('/usr/bin/ditto/foo/bar///bar/'), ('/usr/bin/ditto', 'foo/bar/bar'))
        self.assertEqual(zipio._locate('/usr/bin/ditto///foo/bar///bar/'), ('/usr/bin/ditto', 'foo/bar/bar'))
        self.assertRaises(IOError, zipio._locate, '/usr/bin/ditto.bar')
        self.assertRaises(IOError, zipio._locate, '/foo/bar/baz.txt')

    def test_open(self):
        # 1. Regular file
        fp = zipio.open(os.path.join(TESTDATA, 'test.txt'), 'r')
        data = fp.read()
        fp.close()
        self.assertEqual(data, 'This is test.txt\n')

        if sys.version_info[0] == 3:
            fp = zipio.open(os.path.join(TESTDATA, 'test.txt'), 'rb')
            data = fp.read()
            fp.close()
            self.assertEqual(data, b'This is test.txt\n')

        # 2. File inside zipfile
        fp = zipio.open(os.path.join(TESTDATA, 'zipped.egg', 'test.txt'), 'r')
        data = fp.read()
        fp.close()
        self.assertEqual(data, 'Zipped up test.txt\n')

        if sys.version_info[0] == 3:
            fp = zipio.open(os.path.join(TESTDATA, 'zipped.egg', 'test.txt'), 'rb')
            data = fp.read()
            fp.close()
            self.assertEqual(data, b'Zipped up test.txt\n')

        # 3. EXC: Directory inside zipfile
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'zipped.egg', 'subdir'))
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'zipped.egg', 'subdir2'))
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'zipped.egg', 'subdir2/subdir'))
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'zipped.egg', 'subdir3'))
        # TODO: Add subdir4/file.txt, without directory entry
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'zipped.egg', 'subdir4'))

        # 4. EXC: No such file in zipfile
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'zipped.egg', 'no-such-file'))
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'zipped.egg', 'subdir/no-such-file'))

        # 5. EXC: No such regular file
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'no-such-file.txt'))

        # 6. EXC: Open r/w
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'test.txt'), 'w')
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'test.txt'), 'a')
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'test.txt'), 'r+')
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'test.txt'), 'w+')
        self.assertRaises(IOError, zipio.open, os.path.join(TESTDATA, 'test.txt'), 'a+')

    def test_listdir(self):
        # 1. Regular directory
        self.assertEqual(set(os.listdir(os.path.join(TESTDATA, 'subdir'))), set(['file1.txt', 'file2.txt']))

        # 2. Zipfile with files in directory
        self.assertEqual(set(zipio.listdir(os.path.join(TESTDATA, 'zipped.egg'))), set([
            'test.txt', 'subdir', 'subdir2', 'subdir3', 'subdir4']))

        # 3. Zipfile with files in subdirectory
        self.assertEqual(set(zipio.listdir(os.path.join(TESTDATA, 'zipped.egg', 'subdir'))), set(['file1.txt', 'file2.txt']))
        self.assertEqual(set(zipio.listdir(os.path.join(TESTDATA, 'zipped.egg', 'subdir2'))), set(['subdir']))
        self.assertEqual(set(zipio.listdir(os.path.join(TESTDATA, 'zipped.egg', 'subdir4', 'subdir6'))), set(['mydir']))

        # 4. Zipfile with entry for directory, no files
        self.assertEqual(set(zipio.listdir(os.path.join(TESTDATA, 'zipped.egg', 'subdir3'))), set([]))

        # 5. EXC: Zipfile without directory
        self.assertRaises(IOError, zipio.listdir, os.path.join(TESTDATA, 'zipped.egg', 'subdir10'))

        # 6. EXC: Regular directory doesn't exist
        self.assertRaises(IOError, zipio.listdir, os.path.join(TESTDATA, 'subdir10'))

    def test_isfile(self):
        self.assertTrue(zipio.isfile(os.path.join(TESTDATA, 'test.txt')))
        self.assertFalse(zipio.isfile(os.path.join(TESTDATA, 'subdir')))
        self.assertRaises(IOError, zipio.isfile, os.path.join(TESTDATA, 'no-such-file'))
        self.assertFalse(zipio.isfile(os.path.join(TESTDATA, 'zipped.egg')))
        self.assertFalse(zipio.isfile(os.path.join(TESTDATA, 'zipped.egg', 'subdir4')))
        self.assertTrue(zipio.isfile(os.path.join(TESTDATA, 'zipped.egg', 'test.txt')))
        self.assertFalse(zipio.isfile(os.path.join(TESTDATA, 'zipped.egg', 'subdir')))
        self.assertRaises(IOError, zipio.isfile, os.path.join(TESTDATA, 'zipped.egg', 'no-such-file'))
        self.assertTrue(zipio.isfile(os.path.join(TESTDATA, 'zipped.egg', 'subdir2', 'subdir', 'file1.txt')))

    def test_isdir(self):
        self.assertTrue(zipio.isdir(TESTDATA))
        self.assertFalse(zipio.isdir(os.path.join(TESTDATA, 'test.txt')))
        self.assertTrue(zipio.isdir(os.path.join(TESTDATA, 'zipped.egg')))
        self.assertTrue(zipio.isdir(os.path.join(TESTDATA, 'zipped.egg', 'subdir')))
        self.assertTrue(zipio.isdir(os.path.join(TESTDATA, 'zipped.egg', 'subdir2/subdir')))
        self.assertTrue(zipio.isdir(os.path.join(TESTDATA, 'zipped.egg', 'subdir4')))
        self.assertFalse(zipio.isdir(os.path.join(TESTDATA, 'zipped.egg', 'subdir4', 'file.txt')))
        self.assertRaises(IOError, zipio.isdir, os.path.join(TESTDATA, 'no-such-file'))
        self.assertRaises(IOError, zipio.isdir, os.path.join(TESTDATA, 'zipped.egg', 'no-such-file'))
        self.assertRaises(IOError, zipio.isdir, os.path.join(TESTDATA, 'zipped.egg', 'subdir', 'no-such-file'))

    def test_islink(self):
        fn = os.path.join(TESTDATA, 'symlink')
        os.symlink('test.txt', fn)
        try:
            self.assertTrue(zipio.islink(fn))

        finally:
            os.unlink(fn)

        self.assertFalse(zipio.islink(os.path.join(TESTDATA, 'test.txt')))
        self.assertFalse(zipio.islink(os.path.join(TESTDATA, 'subdir')))
        self.assertFalse(zipio.islink(os.path.join(TESTDATA, 'zipped.egg')))
        self.assertFalse(zipio.islink(os.path.join(TESTDATA, 'zipped.egg/subdir')))
        self.assertFalse(zipio.islink(os.path.join(TESTDATA, 'zipped.egg/subdir4')))
        self.assertFalse(zipio.islink(os.path.join(TESTDATA, 'zipped.egg/test.txt')))
        self.assertFalse(zipio.islink(os.path.join(TESTDATA, 'zipped.egg/subdir/file1.txt')))

        self.assertRaises(IOError, zipio.islink, os.path.join(TESTDATA, 'no-such-file'))
        self.assertRaises(IOError, zipio.islink, os.path.join(TESTDATA, 'zipped.egg', 'no-such-file'))


    def test_readlink(self):
        fn = os.path.join(TESTDATA, 'symlink')
        os.symlink('test.txt', fn)
        try:
            self.assertEqual(zipio.readlink(fn), 'test.txt')

        finally:
            os.unlink(fn)

        self.assertRaises(OSError, zipio.readlink, os.path.join(TESTDATA, 'test.txt'))
        self.assertRaises(OSError, zipio.readlink, os.path.join(TESTDATA, 'subdir'))
        self.assertRaises(OSError, zipio.readlink, os.path.join(TESTDATA, 'zipped.egg'))
        self.assertRaises(OSError, zipio.readlink, os.path.join(TESTDATA, 'zipped.egg', 'subdir4'))
        self.assertRaises(OSError, zipio.readlink, os.path.join(TESTDATA, 'zipped.egg', 'no-such-file'))
        self.assertRaises(OSError, zipio.readlink, os.path.join(TESTDATA, 'zipped.egg', 'subdir/no-such-file'))

    def test_getmtime(self):
        fn = os.path.join(TESTDATA, 'test.txt')
        self.assertEqual(os.path.getmtime(fn), zipio.getmtime(fn))

        fn = os.path.join(TESTDATA, 'zipped.egg')
        self.assertEqual(os.path.getmtime(fn), zipio.getmtime(fn))

        fn = os.path.join(TESTDATA, 'zipped.egg/test.txt')
        self.assertIn(zipio.getmtime(fn), (1300193680.0, 1300222480.0))

        fn = os.path.join(TESTDATA, 'zipped.egg/subdir')
        self.assertIn(zipio.getmtime(fn), (1300193890.0, 1300222690.0))

        fn = os.path.join(TESTDATA, 'zipped.egg/subdir4')
        self.assertEqual(zipio.getmtime(fn), os.path.getmtime(os.path.join(TESTDATA, 'zipped.egg')))

        self.assertRaises(IOError, zipio.getmtime, os.path.join(TESTDATA, 'no-file'))
        self.assertRaises(IOError, zipio.getmtime, os.path.join(TESTDATA, 'zipped.egg/no-file'))

    def test_contextlib(self):
        # 1. Regular file
        with zipio.open(os.path.join(TESTDATA, 'test.txt'), 'r') as fp:
            data = fp.read()
        try:
            fp.read()
            self.fail("file not closed")
        except (ValueError, IOError):
            pass

        self.assertEqual(data, 'This is test.txt\n')

        if sys.version_info[0] == 3:
            with zipio.open(os.path.join(TESTDATA, 'test.txt'), 'rb') as fp:
                data = fp.read()
            try:
                fp.read()
                self.fail("file not closed")
            except (ValueError, IOError):
                pass

            self.assertEqual(data, b'This is test.txt\n')

        # 2. File inside zipfile
        with zipio.open(os.path.join(TESTDATA, 'zipped.egg', 'test.txt'), 'r') as fp:
            data = fp.read()
        try:
            fp.read()
            self.fail("file not closed")
        except (ValueError, IOError):
            pass
        self.assertEqual(data, 'Zipped up test.txt\n')

        if sys.version_info[0] == 3:
            with zipio.open(os.path.join(TESTDATA, 'zipped.egg', 'test.txt'), 'rb') as fp:
                data = fp.read()
            try:
                fp.read()
                self.fail("file not closed")
            except (IOError, ValueError):
                pass
            self.assertEqual(data, b'Zipped up test.txt\n')

if __name__ == "__main__":
    unittest.main()
