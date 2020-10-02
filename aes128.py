from cipher import BlockCipher
"""
Naveh Marchoom 312275746
"""

BLOCK_SIZE = 16
RG_FIELD = 0x1b
NUM_ROUNDS = 10
R_CON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
S_BOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
         0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
         0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
         0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
         0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
         0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
         0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
         0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
         0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
         0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
         0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
         0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
         0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
         0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
         0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
         0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
R_BOX = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
         0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
         0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
         0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
         0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
         0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
         0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
         0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
         0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
         0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
         0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
         0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
         0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
         0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
         0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
         0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]


class AES128(BlockCipher):
    """
    A singleton class implementing the Advanced Encryption Standard algorithm for encrypting a 16B string.
    Implements the Encrypter interface.
    """
    block_size = BLOCK_SIZE
    __instance: BlockCipher = None

    """
    In order to set AES as a singleton, I made his __new__ function to just return an instance
    of the class if exists, else make a new instance.
    """
    def __new__(cls):
        if cls.__instance is None:
            AES128.__instance = object.__new__(cls)
        return AES128.__instance

    """
    Given a 16B hex string and a 16B key, encrypt the string using AES encryption algorithm.
    """
    @classmethod
    def cipher(cls, plain_text: bytes, key: bytes) -> bytes:
        cls.guard_size(plain_text, key)
        plain_text = cls.__4x4_transpose(plain_text)
        expanded_key = cls.generate_expanded_key(key)
        state = cls.rijndael(plain_text, expanded_key, NUM_ROUNDS)
        return cls.__4x4_transpose(state)

    """
    """
    @classmethod
    def rijndael(cls, byte_array: bytes, expanded_key: list, num_rounds: int):
        state = cls.add_round_key(byte_array, expanded_key[0])
        for i in range(num_rounds):
            state = cls.round(state, expanded_key[i + 1], (i == num_rounds - 1))
        return state


    """
    Run a full AES round on given hex string.
    """
    @classmethod
    def round(cls, state: bytes, round_key: bytes, last_round: bool = False) -> bytes:
        state = cls.byte_substitution(state)
        state = cls.row_shift(state)
        state = cls.mix_columns(state) if not last_round else state
        state = cls.add_round_key(state, round_key)
        return state


    """
    Given a 16B cipher string which was encrypted using AES algorithm and the 16B key used for the encryption,
    decrypts the cipher string.
    """
    @classmethod
    def decipher(cls, cipher_text: bytes, key: bytes) -> bytes:
        cls.guard_size(cipher_text, key)
        cipher_text = cls.__4x4_transpose(cipher_text)
        expanded_key = cls.generate_expanded_key(key)
        state = cls.reverse_rijndael(cipher_text, expanded_key, NUM_ROUNDS)
        return cls.__4x4_transpose(state)

    """
    """
    @classmethod
    def reverse_rijndael(cls, byte_array: bytes, expanded_key: list, num_rounds: int) -> bytes:
        state = cls.add_round_key(byte_array, expanded_key[num_rounds])
        for i in range(num_rounds - 1, -1, -1):
            state = cls.reverse_round(state, expanded_key[i], i + 1, (i == 0))
        return state

    """
    Run a full reverse AES round on given cipher string.
    """
    @classmethod
    def reverse_round(cls, state: bytes, round_key: bytes, nround, last_round: bool = False) -> bytes:
        state = cls.reverse_row_shift(state)
        state = cls.reverse_byte_substitution(state)
        state = cls.add_round_key(state, round_key)
        state = cls.reverse_mix_columns(state) if not last_round else state
        return state

    """
    Replaces each byte in an hex array with the corresponding byte in s_box.
    """
    @classmethod
    def byte_substitution(cls, byte_array: bytes) -> bytes:
        return bytes([S_BOX[byte] for byte in byte_array])

    """
    Replaces each byte in the hex array with the corresponding byte in r_box.
    """
    @classmethod
    def reverse_byte_substitution(cls, byte_array: bytes) -> bytes:
        return bytes([R_BOX[byte] for byte in byte_array])

    """
    Shift the bytes in the hex array in the following manner for each 4 bytes:
    Each 1st byte doesn't shift. Each 2nd byte is shifted 4 to the left. Each 3rd byte is shifted 8 to the left.
    Each 4th byte is shifted 12 to the left.
    """
    @classmethod
    def row_shift(cls, byte_array: bytes) -> bytes:
        temp = [byte_array[i:i + 4] for i in range(0, BLOCK_SIZE, 4)]
        return bytes([temp[i][(j + i) % 4] for i in range(4) for j in range(4)])

    """
    Reverse the shifting done in row_shift method.
    """
    @classmethod
    def reverse_row_shift(cls, byte_array: bytes) -> bytes:
        temp = [byte_array[i:i + 4] for i in range(0, BLOCK_SIZE, 4)]
        return bytes([temp[i][(j - i) % 4] for i in range(4) for j in range(4)])

    """
    Apply the mix_column method on each column from a 4x4 representation of the byte array.
    """
    @classmethod
    def mix_columns(cls, byte_array: bytes) -> bytes:
        # return bytes([cls.mix_column(byte_array[i:i+16:4])[j] for i in range(4) for j in range(4)])
        return cls.__4x4_transpose(bytes([byte for i in range(4) for byte in cls.mix_column(byte_array[i:i+16:4])]))

    """
    Apply the mix column algorithm:
    """
    @classmethod
    def mix_column(cls, byte_array: bytes) -> bytes:
        return bytes([cls.__g_mul(byte_array[0], 0x02) ^ cls.__g_mul(byte_array[3], 0x01) ^
                      cls.__g_mul(byte_array[2], 0x01) ^ cls.__g_mul(byte_array[1], 0x03),
                      cls.__g_mul(byte_array[1], 0x02) ^ cls.__g_mul(byte_array[0], 0x01) ^
                      cls.__g_mul(byte_array[3], 0x01) ^ cls.__g_mul(byte_array[2], 0x03),
                      cls.__g_mul(byte_array[2], 0x02) ^ cls.__g_mul(byte_array[1], 0x01) ^
                      cls.__g_mul(byte_array[0], 0x01) ^ cls.__g_mul(byte_array[3], 0x03),
                      cls.__g_mul(byte_array[3], 0x02) ^ cls.__g_mul(byte_array[2], 0x01) ^
                      cls.__g_mul(byte_array[1], 0x01) ^ cls.__g_mul(byte_array[0], 0x03)])

    """
    Apply the reverse mix column algorithm on each column from a 4x4 representation of the byte array
    """
    @classmethod
    def reverse_mix_columns(cls, byte_array: bytes) -> bytes:
        byte_array = cls.__4x4_transpose(byte_array)
        return cls.__4x4_transpose(
            bytes([byte for i in range(0, 16, 4) for byte in cls.reverse_mix_column(byte_array[i:i + 4])]))

    """
    Reverse the mix column algorithm.
    """
    @classmethod
    def reverse_mix_column(cls, byte_array: bytes) -> bytes:
        # print([b for b in byte_array])
        return bytes([cls.__g_mul(byte_array[0], 0x0E) ^ cls.__g_mul(byte_array[3], 0x09) ^
                      cls.__g_mul(byte_array[2], 0x0D) ^ cls.__g_mul(byte_array[1], 0x0B),
                      cls.__g_mul(byte_array[1], 0x0E) ^ cls.__g_mul(byte_array[0], 0x09) ^
                      cls.__g_mul(byte_array[3], 0x0D) ^ cls.__g_mul(byte_array[2], 0x0B),
                      cls.__g_mul(byte_array[2], 0x0E) ^ cls.__g_mul(byte_array[1], 0x09) ^
                      cls.__g_mul(byte_array[0], 0x0D) ^ cls.__g_mul(byte_array[3], 0x0B),
                      cls.__g_mul(byte_array[3], 0x0E) ^ cls.__g_mul(byte_array[2], 0x09) ^
                      cls.__g_mul(byte_array[1], 0x0D) ^ cls.__g_mul(byte_array[0], 0x0B)])

    """
    Xor the round's key with current state.
    """
    @classmethod
    def add_round_key(cls, byte_array: bytes, round_key: bytes) -> bytes:
        return bytes([byte_array[i] ^ round_key[i] for i in range(BLOCK_SIZE)])

    """
    Generates an expanded key.
    """
    @classmethod
    def generate_expanded_key(cls, key: bytes) -> list:
        word_array = [key[i:i + 4] for i in range(0, len(key), 4)]  # The expansion algorithm iterate over 4B words.
        for i in range(len(word_array), (NUM_ROUNDS + 1) * 4):  # We need 11 keys of 4x4B words each:
            word = word_array[i - 1]
            if i % 4 == 0:
                word = cls.__rotate_bytes_left(word)
                word = cls.byte_substitution(word)
                word = bytes([word[0] ^ R_CON[int(i / 4) - 1]] + [byte for byte in word[1:]])
            word = bytes([word[j] ^ word_array[i - 4][j] for j in range(len(word))])
            word_array.insert(i, word)
        byte_array = [byte for i in range(len(word_array)) for byte in word_array[i]]
        # merge the words back to 16B keys:
        return [cls.__4x4_transpose(bytes(byte_array[i:i+16])) for i in range(0, len(byte_array), 16)]

    """
    Given a series of strings, raise exception if one of their length isn't block_size.
    """
    @staticmethod
    def guard_size(*args):
        for var in args:
            if type(var) == str and len(var) != BLOCK_SIZE * 2:
                raise Exception("String size must be 16B")

    """
    Transpose the byte array as a 4x4 array
    """
    @staticmethod
    def __4x4_transpose(byte_array: bytes) -> bytes:
        return bytes([byte_array[i * 4 + j] for j in range(4) for i in range(4)])

    """
    Multiplies 2 bytes in the Galois Field.
    """
    @staticmethod
    def __g_mul(byte1: int, byte2: int) -> int:
        ret_byte = 0x00
        for i in range(8):
            ret_byte = ret_byte ^ byte1 if (byte2 & 0x01) != 0 else ret_byte
            byte1 = (byte1 << 1) ^ RG_FIELD if (byte1 & 0x80) != 0 else byte1 << 1
            byte2 >>= 1
        return ret_byte % 256
    """
    rotates an array to the left a specific amount of times.
    """
    @staticmethod
    def __rotate_bytes_left(array: bytes) -> bytes:
        return bytes([array[(i + 1) % len(array)] for i in range(len(array))])
