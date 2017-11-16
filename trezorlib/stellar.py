import base64
import struct

def get_public_key_from_bytes(pk_bytes):
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

    count = 0
    for byte in bytes:
        count = count + 1

        for i in range(0, 8):
            bit = ((byte >> (7 - i) & 1) == 1)
            c15 = ((crc >> 15 & 1) == 1)
            crc <<= 1
            if c15 ^ bit:
                crc ^= polynomial

    return crc & 0xffff