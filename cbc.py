"""
Naveh Marchoom 312275746
"""
from cipher import BlockCipher, ModeOfOperation


class CBC(ModeOfOperation):
    """
    A class implementing the Cipher Block Chaining mode of operation algorithm.
    Implements the ModeOfOperation interface.
    """
    def __init__(self, block_cipher: BlockCipher, key: bytes, iv: bytes):
        self.block_cipher = block_cipher
        self.key = key
        self.iv = iv

    def cipher(self, plain_text: bytes) -> bytes:
        cipher_text = bytes(0)
        blocks = CBC.split_to_blocks(
            CBC.pad_text(plain_text, self.block_cipher.block_size), self.block_cipher.block_size)
        c = self.iv
        for block in blocks:
            c = self.block_cipher.cipher(CBC.xor(block, c), self.key)
            cipher_text += c
        return cipher_text

    def decipher(self, cipher_text: bytes) -> bytes:
        plain_text = bytes(0)
        blocks = CBC.split_to_blocks(cipher_text, self.block_cipher.block_size)
        c = self.iv
        for block in blocks:
            plain_text += self.xor(self.block_cipher.decipher(block, self.key), c)
            c = block
        return plain_text

    @staticmethod
    def pad_text(byte_array: bytes, block_size: int) -> bytes:
        if len(byte_array) % block_size != 0:
            byte_array += bytes(block_size - len(byte_array) % block_size)
        return byte_array

    @staticmethod
    def split_to_blocks(byte_array: bytes, block_size: int) -> list:
        return [byte_array[i:i + block_size] for i in range(0, len(byte_array), block_size)]

    @staticmethod
    def xor(block1: bytes, block2: bytes) -> bytes:
        assert len(block1) == len(block2)
        return bytes([block1[i] ^ block2[i] for i in range(len(block1))])
