import base64
import struct
import binascii

def get_index_from_account_number(account):
    """Returns an integer index or the default of 0"""
    max_account_index = pow(2, 31) - 1

    if account is None:
        index = 0
    else:
        index = int(account) - 1

    if index < 0 or index > max_account_index:
        raise ValueError("Error: invalid account number (must be between 1 and " + str(max_account_index) + ")")

    return index


def address_from_public_key(pk_bytes):
    """Returns the base32-encoded version of pk_bytes (G...)
    """
    final_bytes = bytearray()

    # version
    final_bytes.append(6 << 3)
    # public key
    final_bytes.extend(pk_bytes)
    # checksum
    final_bytes.extend(struct.pack("<H", _crc16_checksum(final_bytes)))

    return base64.b32encode(final_bytes)

def _crc16_checksum(bytes):
    """Returns the CRC-16 checksum of bytearray bytes

    Ported from Java implementation at: http://introcs.cs.princeton.edu/java/61data/CRC16CCITT.java.html

    Initial value changed to 0x0000 to match Stellar configuration.
    """
    crc = 0x0000
    polynomial = 0x1021

    for byte in bytes:
        for i in range(0, 8):
            bit = ((byte >> (7 - i) & 1) == 1)
            c15 = ((crc >> 15 & 1) == 1)
            crc <<= 1
            if c15 ^ bit:
                crc ^= polynomial

    return crc & 0xffff