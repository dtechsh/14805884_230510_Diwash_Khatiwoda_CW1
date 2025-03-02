import unittest
from main_stegno import encrypt_message, decrypt_message, message_to_binary, binary_to_message

class TestStegFunctions(unittest.TestCase):

    def test_encrypt_decrypt_message(self):
        key = b"thisisasecretkey"
        message = "Hello, Steganography!"
        encrypted = encrypt_message(message, key)
        decrypted = decrypt_message(encrypted, key)
        self.assertEqual(decrypted, message)

    def test_message_to_binary(self):
        self.assertEqual(message_to_binary("A"), "01000001")
        self.assertEqual(message_to_binary("AB"), "0100000101000010")

    def test_binary_to_message(self):
        self.assertEqual(binary_to_message("01000001"), "A")
        self.assertEqual(binary_to_message("0100000101000010"), "AB")

if __name__ == "__main__":
    unittest.main()
