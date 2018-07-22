import unittest

from Generator import Generator
from Verifier import Verifier


class Test(unittest.TestCase):
    user_code = "koen@koenvh.nl"
    doc_code = "B55BFB61790E8D4B66660501E9945ED9B33BE1D5"

    def test_generate_and_verify(self):
        g = Generator(user_code=self.user_code, doc_code=self.doc_code)
        keys = g.generate_all()
        self.assertEqual([51758917, 54791839, 86087042], keys)
        # codes = [51758917, 54791839, 86087042]
        v = Verifier(user_code=self.user_code, doc_code=self.doc_code, keys=keys)
        self.assertEqual([True, True, True], v.verify_all())


if __name__ == "__main__":
    unittest.main()
