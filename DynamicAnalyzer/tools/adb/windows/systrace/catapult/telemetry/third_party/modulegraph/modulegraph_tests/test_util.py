import unittest
import encodings
import encodings.aliases
from modulegraph import util
import sys

try:
    from io import BytesIO
except ImportError:
    from cStringIO import StringIO as BytesIO

class TestUtil (unittest.TestCase):
    def test_imp_find_module(self):
        fn = util.imp_find_module('encodings.aliases')[1]
        self.assertTrue(encodings.aliases.__file__.startswith(fn))

    def test_imp_walk(self):
        imps = list(util.imp_walk('encodings.aliases'))
        self.assertEqual(len(imps), 2)

        self.assertEqual(imps[0][0], 'encodings')
        self.assertTrue(encodings.__file__.startswith(imps[0][1][1]))

        self.assertEqual(imps[1][0], 'aliases')
        self.assertTrue(encodings.aliases.__file__.startswith(imps[1][1][1]))

        # Close all files, avoid warning by unittest
        for i in imps:
            if i[1][0] is not None:
                i[1][0].close()


    def test_guess_encoding(self):
        fp = BytesIO(b"# coding: utf-8")
        self.assertEqual(util.guess_encoding(fp), "utf-8")

        fp = BytesIO(b"\n# coding: utf-8")
        self.assertEqual(util.guess_encoding(fp), "utf-8")

        fp = BytesIO(b"# coding: latin-1")
        self.assertEqual(util.guess_encoding(fp), "latin-1")

        fp = BytesIO(b"\n# coding: latin-1")
        self.assertEqual(util.guess_encoding(fp), "latin-1")

        fp = BytesIO(b"#!/usr/bin/env/python\n# vim: set fileencoding=latin-1 :")
        self.assertEqual(util.guess_encoding(fp), "latin-1")

        fp = BytesIO(b"\n\n\n# coding: latin-1")
        if sys.version_info[0] == 2:
            self.assertEqual(util.guess_encoding(fp), "ascii")
        else:
            self.assertEqual(util.guess_encoding(fp), "utf-8")

        del fp


if __name__ == "__main__":
    unittest.main()
