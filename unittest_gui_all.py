import unittest
from gui_all import (
    hash_password,
    verify_password,
    validate_name,
    validate_gmail,
    validate_username,
    validate_password,
)

class TestSteganographyTool(unittest.TestCase):

    def test_hash_password(self):
        password = "Test@123"
        hashed = hash_password(password)
        self.assertIsInstance(hashed, str)
        self.assertTrue(verify_password(hashed, password))
        self.assertFalse(verify_password(hashed, "Wrong@123"))
        with self.assertRaises(ValueError):
            hash_password("")
        with self.assertRaises(ValueError):
            hash_password(None)

    def test_verify_password(self):
        password = "Test@123"
        hashed = hash_password(password)
        self.assertTrue(verify_password(hashed, password))
        self.assertFalse(verify_password(hashed, "Wrong@123"))
        with self.assertRaises(ValueError):
            verify_password(hashed, None)
        with self.assertRaises(ValueError):
            verify_password(None, password)

    def test_validate_name(self):
        self.assertTrue(validate_name("John"))
        self.assertFalse(validate_name("john"))
        self.assertFalse(validate_name("J"))
        self.assertFalse(validate_name("John123"))
        self.assertFalse(validate_name(""))
        self.assertFalse(validate_name(None))

    def test_validate_gmail(self):
        self.assertTrue(validate_gmail("test123@gmail.com"))
        self.assertFalse(validate_gmail("test@outlook.com"))
        self.assertFalse(validate_gmail("t@gmail.com"))
        self.assertFalse(validate_gmail(""))
        self.assertFalse(validate_gmail(None))

    def test_validate_username(self):
        self.assertTrue(validate_username("user123!"))
        self.assertFalse(validate_username("user"))
        self.assertFalse(validate_username("u!1"))
        self.assertFalse(validate_username(""))
        self.assertFalse(validate_username(None))

    def test_validate_password(self):
        self.assertTrue(validate_password("Password123!"))
        self.assertFalse(validate_password("password123"))
        self.assertFalse(validate_password("Pw1!"))
        self.assertFalse(validate_password(""))
        self.assertFalse(validate_password(None))

if __name__ == '__main__':
    unittest.main()