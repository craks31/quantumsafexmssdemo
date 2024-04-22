from XMSS import *
import hashlib
import sys
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

    # Prompt the user for input

    cardholder_name = input("Enter cardholder name: ")


    def is_valid_credit_card_number(card_number):
        return card_number.isdigit() and len(card_number) == 16 # Check if all characters are digits


    def is_valid_expiry_date(expiry_date):
        return expiry_date.isdigit() and len(expiry_date) == 4  # Check if all characters are digits and length is 4

    def is_valid_cvv(cvv):
        return expiry_date.isdigit() and len(cvv) == 3  # Check if all characters are digits and length is 4


    # Prompt the user for input and validate
    while True:
        credit_card_number = input("Enter credit card number as XXXXXXXXXXXXXXXX: ")
        if is_valid_credit_card_number(credit_card_number):
            break
        else:
            print("Invalid credit card number. Please enter ATLEAST 16 digits ONLY.")

    while True:
        expiry_date = input("Enter expiry date as MMYY: ")
        if is_valid_expiry_date(expiry_date):
            break
        else:
            print("Invalid expiry date. Please enter 4 digits representing MMYY.")

    while True:
        cvv = input("Enter security code or cvv as XXX: ")
        if is_valid_cvv(cvv):
            break
        else:
            print("Invalid cvv. Please enter 3 digits representing XXX.")
    # Construct a dictionary
    credit_card_info = {
        "credit_card_number": credit_card_number,
        "expiry_date": expiry_date,
        "cvv": cvv,
        "cardholder_name": cardholder_name
    }

    json_string = json.dumps(credit_card_info)
    sha256_digest = hashlib.sha256(json_string.encode()).digest()
    byte_array_data = bytearray(sha256_digest)
    print("_" * 40)
    XMSS_demo([byte_array_data])
