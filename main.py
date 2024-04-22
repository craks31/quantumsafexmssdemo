from XMSS import *
import hashlib
import json


def XMSS_demo(messages: List[bytearray]):

    height = int(log2(len(messages)))
    msg_len = len(messages[0]) // 2
    w = 16

    keyPair = XMSS_keyGen(height, msg_len, w)

    addressXMSS = ADRS()

    signatures = []

    for message in messages:
        signature = XMSS_sign(message, keyPair.SK, w, addressXMSS, height)
        signatures.append(signature)

    ifProved = True

    for signature, message in zip(signatures, messages):
        if not XMSS_verify(signature, message, keyPair.PK, w, keyPair.PK.SEED, height):
            ifProved = False
            break

    print("XMSS verification result:")
    print("Proved: " + str(ifProved))


if __name__ == '__main__':
    message = {
        "card_number": "1234567890123459",
        "expiry_date": "12/25",
        "cvv": "123",
        "name": "Jon Doe"
    }
    json_string = json.dumps(message)
    sha256_digest = hashlib.sha256(json_string.encode()).digest()
    byte_array_data = bytearray(sha256_digest)
    print("_" * 40)
    XMSS_demo([byte_array_data])
