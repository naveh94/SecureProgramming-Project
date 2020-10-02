from project import cbc_custom_decrypt, cbc_flip_fix

testsing_dict_decrypt = [{
    "key": b"1111111111111111",
    "iv": b"2222222222222222",
    "plain": [b"hello to you!, task completed!!!", b"you can make your day abcdefpoqa"],
    "cipher": [b"\xae('\x17\xc0<\xcan%\x83\xdf\xae\xddg\xf3\x864\x97\xa3\xc9\x01\x81a\x9e\x0b\x96\x05\x0f\xc3P\x8b\x06",
               b'\x11\xb3\x8e\xb3,/\x92\x01\x9b\x97\x8b\x05\xdd\xa9\xc6\xebl\xbc\x98\xd80p\x10\xf9o\xfc\x89^p\xd1V\x99']
},
    {
        "key": b"1123411115461190",
        "iv": b"9122622795742201",
        "plain": [b"hello to you!, task completed!!!", b"you can make your day abcdefpoqa"],
        "cipher": [b'\xeb+\xd0\xd2\x04\x9d\x9b\x0c\xe3Dez\xff\x03\xdfd\xa8\x9f{3&5P\x95\xf5\x15*x\xdc!\x978',
                   b'0\x94\x9e6\xb6\xf2+\xaeMyb\x1f\x94\xea\xcd\x84s\x98\x99\xe0\xda`U\x8d6\x91\x1a\x00S\x7f{=']
    }
]
testsing_dict_flipped = [
    {
        "key": b"0023498705461190",
        "iv": b"9155622795743333",
        "original_message": [
            b'bbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaddddddddddddddddfffffffffffffffftttttttttttttttt',
            # changed the ** last ** bit of dddddddd
            b"bbbbbbbbbbbbbbbbccccccccccccccccyyyyyyyyyyyyyyyydddddddddddddddd"  # changed arr_of_y[10]
        ],
        "corrupted_cipher": [
            b'\x83\xdb-\x81gU\xea\xa6\x0c\xbe\xb7\xde\x05\xfb\xa6\x9d\xca\x926B"-K\x13=sO\x07R\xf8\x92\x94O41o\x9cU~mU\xcc\x88u\xae\x85\x8f\xbf\xfdn\x86\x7f\xc2$\xf6\xeb=\x8b\xff\x9b\x0e9sj',
            b'\x83\xdb-\x81gU\xea\xa6\x0c\xbe\xb7\xde\x05\xfb\xa6\x9dL\x9b\xefQ_fg(c\x11jp\xfa\xff\x01\xb0\x1e\xbb\x88\x89\xfe\xc3W\xcb7\xf6~\x0f\xa5\xff\x97\xb8Ob\xa0\xc8\xd6\x93/\x0f\xcd)-!\xadXw{'
        ],
        "block_to_return": [
            b"dddddddddddddddd",
            b"yyyyyyyyyyyyyyyy"
        ]
    },
    {
        "key": b"1234598705461190",
        "iv": b"1234562795743333",
        "original_message": [
            b'bbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaddddddddddddddddfffffffffffffffftttttttttttttttt',
            # changed the ** first ** bit of bbbbbbbb
        ],
        "corrupted_cipher": [
            b'\x1a\x7f\x9c>H\x97\n\xac\xb0\x06\xd8z\x87\xa5H\xf5.v\x9b\xc9p\x9a\xb9\xaf\x8f\xc4\t\x85>^\xa0\xff\xe3\t\xcf\x9c\xbc\x820\x96\xb1\x0bK[\xd8p\x05\xac\x9ac\xa5\xe1\xd6\xaeRz\x8b\xe3\xd0\xee\xbb\xe36\\',
        ],
        "block_to_return": [
            b"bbbbbbbbbbbbbbbb"
        ]
    }
]

#
# def cbc_custom_decrypt(k, n, cipher):
#     raise NotImplementedError
#
#
# def cbc_flip_fix(k, n, cipher):
#     raise NotImplementedError


def testing_decrypt(testsing_dict):
    errors = 1
    test_num = 1
    for test in testsing_dict:
        key, iv = test["key"], test["iv"]
        for plain_text, c in zip(test["plain"], test["cipher"]):
            num_of_blocks = len(c) // 16
            my_output = cbc_custom_decrypt(key, num_of_blocks, iv + c)
            if my_output != plain_text:
                print("Error #{} in Test #{}".format(errors, test_num))
                print("in: {}\n\tplain text should be: {}\n\tcipher is: {}\n".format(errors, my_output, plain_text, c))
                errors += 1
            else:
                print("Passed Test #{}".format(test_num))
            test_num += 1
    if errors == 1:
        print("Passed The Test: testing_decrypt")
    else:
        print("Didn't Pass The Test")


def testing_flip(testsing_dict_flipped):
    errors = 1
    test_num = 1
    for test in testsing_dict_flipped:
        key, iv = test["key"], test["iv"]
        for answer, c in zip(test["block_to_return"], test["corrupted_cipher"]):
            num_of_blocks = len(c) // 16
            my_output = cbc_flip_fix(key, num_of_blocks, iv + c)
            if my_output != answer:
                print("Error #{} in Test #{}".format(errors, test_num))
                print("my output: {}\n\toriginal block is: {}\n".format(my_output, answer))
                errors += 1
            else:
                print("Passed Test #{}".format(test_num))
            test_num += 1
    if errors == 1:
        print("Passed The Test")
    else:
        print("Didn't Pass The Test")


if __name__ == "__main__":
    testing_decrypt(testsing_dict_decrypt)
    testing_flip(testsing_dict_flipped)
