import unittest
from login_signup import validate_name, validate_gmail, validate_username, validate_password, hash_password, verify_password

class TestAuthFunctions(unittest.TestCase):

    def test_validate_name(self):
        self.assertTrue(validate_name("John"))
        self.assertFalse(validate_name("john"))  
        self.assertFalse(validate_name("J"))  

    def test_validate_gmail(self):
        self.assertTrue(validate_gmail("testuser@gmail.com"))
        self.assertFalse(validate_gmail("testuser@yahoo.com"))  
        self.assertFalse(validate_gmail("usergmail.com")) 

    def test_validate_username(self):
        self.assertTrue(validate_username("User@123"))
        self.assertFalse(validate_username("User123"))  

    def test_validate_password(self):
        self.assertTrue(validate_password("Strong@123"))
        self.assertFalse(validate_password("weakpassword")) 

    def test_hash_password_and_verify(self):
        password = "Secure@123"
        hashed_pw = hash_password(password)
        self.assertTrue(verify_password(hashed_pw, password))
        self.assertFalse(verify_password(hashed_pw, "WrongPassword"))

if __name__ == "__main__":
    unittest.main()
