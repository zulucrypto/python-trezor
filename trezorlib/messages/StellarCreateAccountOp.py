# Automatically generated by pb2py
from .. import protobuf as p


class StellarCreateAccountOp(p.MessageType):
    FIELDS = {
        1: ('source_account', p.BytesType, 0),
        2: ('new_account', p.BytesType, 0),
        3: ('starting_balance', p.Sint64Type, 0),
    }
    MESSAGE_WIRE_TYPE = 210
