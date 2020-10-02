"""
Naveh Marchoom 312275746
"""


class Cipher:
    """
    A cipher interface.
    """
    cipher: callable
    decipher: callable


class ModeOfOperation(Cipher):
    """
    A mode of operation interface.
    """


class BlockCipher(Cipher):
    """
    A block cipher interface.
    """
    block_size: int
