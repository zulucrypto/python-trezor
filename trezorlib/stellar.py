import base64
import struct
import binascii
import xdrlib
import hexdump

def get_index_from_account_number(account):
    """Returns an integer index or the default of 0"""
    max_account_index = pow(2, 31) - 1

    if account is None:
        index = 0
    else:
        index = int(account) - 1

    if index < 0 or index > max_account_index:
        raise ValueError("Invalid account number (must be between 1 and " + str(max_account_index) + ")")

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

def parse_transaction_bytes(bytes, network_passphrase, account_index):
    """Parses base64data into a StellarSignTx message
    """
    parsed = {}
    parsed["protocol_version"] = 1
    parsed["operations"] = []
    unpacker = xdrlib.Unpacker(bytes)

    parsed["source_account"] = _xdr_read_address(unpacker)
    parsed["fee"] = unpacker.unpack_uint()
    parsed["sequence_number"] = unpacker.unpack_uhyper()

    # Timebounds is an optional field
    parsed["timebounds_start"] = 0
    parsed["timebounds_end"] = 0
    has_timebounds = unpacker.unpack_bool()
    if has_timebounds:
        max_timebound = 2**32-1 # max unsigned 32-bit int (trezor does not support the full 64-bit time value)
        parsed["timebounds_start"] = unpacker.unpack_uhyper()
        parsed["timebounds_end"] = unpacker.unpack_uhyper()

        if parsed["timebounds_start"] > max_timebound or parsed["timebounds_start"] < 0:
            raise ValueError("Starting timebound out of range (must be between 0 and " + max_timebound)
        if parsed["timebounds_end"] > max_timebound or parsed["timebounds_end"] < 0:
            raise ValueError("Ending timebound out of range (must be between 0 and " + max_timebound)

    # memo type determines what optional fields are set
    parsed["memo_type"] = unpacker.unpack_uint()
    parsed["memo_text"] = None
    parsed["memo_id"] = None
    parsed["memo_hash"] = None

    # text
    if parsed["memo_type"] == 1:
        parsed["memo_text"] = unpacker.unpack_string()
    # id (64-bit uint)
    if parsed["memo_type"] == 2:
        parsed["memo_id"] = unpacker.unpack_uhyper()
    # hash / return are the same structure (32 bytes representing a hash)
    if parsed["memo_type"] == 3 or parsed["memo_type"] == 4:
        parsed["memo+hash"] = unpacker.unpack_fopaque(32)

    parsed["num_operations"] = unpacker.unpack_uint()

    for opIdx in range(0, parsed["num_operations"]):
        parsed["operations"].append(_parse_operation_bytes(unpacker))

    return parsed

def _parse_operation_bytes(unpacker):
    """Returns a dictionary describing the next operation as read from
    the byte stream in unpacker
    """
    op = {
        "source_account": None,
        "type": None
    }

    has_source_account = unpacker.unpack_bool()
    if has_source_account:
        op["source_account"] = unpacker.unpack_fopaque(32)

    op["type"] = unpacker.unpack_uint()

    # see: https://github.com/stellar/stellar-core/blob/master/src/xdr/Stellar-transaction.x#L16
    if op["type"] == 0:
        op["destination_account"] = _xdr_read_address(unpacker)
        op["amount"] = unpacker.unpack_hyper()

    if op["type"] == 1:
        op["destination_account"] = _xdr_read_address(unpacker)
        op["asset"] = _xdr_read_asset(unpacker)
        op["amount"] = unpacker.unpack_uhyper()

    return op

def _xdr_read_asset(unpacker):
    """Reads a stellar Asset from unpacker"""
    asset = {
        "type": unpacker.unpack_uint(),
        "code": None,
        "issuer": None
    }

    # alphanum 4
    if asset["type"] == 1:
        asset["code"] = unpacker.unpack_fstring(4)
        asset["issuer"] = _xdr_read_address(unpacker)

    if asset["type"] == 2:
        asset["code"] = unpacker.unpack_fstring(12)
        asset["issuer"] = _xdr_read_address(unpacker)

    return asset


def _xdr_read_address(unpacker):
    """Reads a stellar address and returns the 32-byte
    data representing the address
    """
    # First 4 bytes are the address type
    address_type = unpacker.unpack_uint()
    if address_type != 0:
        raise ValueError("Unsupported address type")

    return unpacker.unpack_fopaque(32)

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