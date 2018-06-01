# This file is part of the TREZOR project.
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.
#
# XDR decoding tool available at:
#   https://www.stellar.org/laboratory/#xdr-viewer
#
# ## Test Info
#
# The default mnemonic generates the following Stellar keypair at path 44'/148'/0':
#   GAK5MSF74TJW6GLM7NLTL76YZJKM2S4CGP3UH4REJHPHZ4YBZW2GSBPW
#   SDE2YU4V2IYSJIUH7MONDYZTSSLDXV5QDEGUUOLCU4TK7CZWTAXZ5CEG
#
# ### Testing a new Operation
#
# 1. Start at the Stellar transaction builder: https://www.stellar.org/laboratory/#txbuilder?network=test
#   (Verify that the "test" network is active in the upper right)
#
# 2. Fill out the fields at the top as follows:
#   Source account: GAK5MSF74TJW6GLM7NLTL76YZJKM2S4CGP3UH4REJHPHZ4YBZW2GSBPW
#   Transaction sequence number: 4294967296 (see _create_msg)
#   Base fee: 100
#   Memo: None
#   Time Bounds: <leave blank>
#
# 3. Select the operation to test, such as Create Account
#
# 4. Fill out the fields for the operation
#
# 5. Scroll down to the bottom of the page and click "Sign in Transaction Signer"
#
# 6. In the first "Add Signer" text box enter the secret key: SDE2YU4V2IYSJIUH7MONDYZTSSLDXV5QDEGUUOLCU4TK7CZWTAXZ5CEG
#
# 7. Scroll down to the bottom and look at the "signatures" section. The Trezor should generate the same signature
#

from base64 import b64encode
from .common import TrezorTest
from .conftest import TREZOR_VERSION
from binascii import hexlify, unhexlify
from trezorlib import messages as proto
from trezorlib import stellar
import pytest


@pytest.mark.stellar
@pytest.mark.xfail(TREZOR_VERSION == 2, reason="T2 support is not yet finished")
class TestMsgStellarSignTransaction(TrezorTest):

    def get_network_passphrase(self):
        """Use the same passphrase as the network that generated the test XDR/signatures"""
        return "Test SDF Network ; September 2015"

    def get_address_n(self):
        """BIP32 path of the default account"""
        return self.client.expand_path("m/44'/148'/0'")

    def test_sign_tx_bump_sequence_op(self):
        self.setup_mnemonic_nopin_nopassphrase()

        op = proto.StellarBumpSequenceOp()
        op.bump_to = 0x7fffffffffffffff
        tx = self._create_msg()

        response = self.client.stellar_sign_transaction(tx, [op], self.get_address_n(), self.get_network_passphrase())
        assert b64encode(response.signature) == b'ZMIfHWhpyXdg40PzwOtkcXYnbZIO12Qy0WvkGqoYpb7jyWbG2HQCG7dgWhCoU5K81pvZTA2pMwiPjMwCXA//Bg=='

    def test_sign_tx_account_merge_op(self):
        self.setup_mnemonic_nopin_nopassphrase()

        op = proto.StellarAccountMergeOp()
        # GBOVKZBEM2YYLOCDCUXJ4IMRKHN4LCJAE7WEAEA2KF562XFAGDBOB64V
        op.destination_account = unhexlify('5d55642466b185b843152e9e219151dbc5892027ec40101a517bed5ca030c2e0')

        tx = self._create_msg()

        response = self.client.stellar_sign_transaction(tx, [op], self.get_address_n(), self.get_network_passphrase())

        assert hexlify(response.public_key) == b'15d648bfe4d36f196cfb5735ffd8ca54cd4b8233f743f22449de7cf301cdb469'
        assert b64encode(response.signature) == b'2R3Pj89U+dWrqy7otUrLLjtANjAg0lmBQL8E+89Po0Y94oqZkauP8j3WE7+/z7vF6XvAMLoOdqRYkUzr2oh7Dg=='

    def test_sign_tx_create_account_op(self):
        """Create new account with initial balance of 100.0333"""
        self.setup_mnemonic_nopin_nopassphrase()

        op = proto.StellarCreateAccountOp()
        op.new_account = stellar.address_to_public_key("GBOVKZBEM2YYLOCDCUXJ4IMRKHN4LCJAE7WEAEA2KF562XFAGDBOB64V")
        op.starting_balance = 1000333000

        tx = self._create_msg()

        response = self.client.stellar_sign_transaction(tx, [op], self.get_address_n(), self.get_network_passphrase())

        assert b64encode(response.signature) == b'vrRYqkM4b54NrDR05UrW7ZHU7CNcidV0fn+bk9dqOW1bCbmX3YfeRbk2Tf1aea8nr9SD0sfBhtrDpdyxUenjBw=='

    def test_sign_tx_payment_op_native(self):
        """Native payment of 50.0111 XLM to GBOVKZBEM2YYLOCDCUXJ4IMRKHN4LCJAE7WEAEA2KF562XFAGDBOB64V"""
        self.setup_mnemonic_nopin_nopassphrase()

        op = proto.StellarPaymentOp()
        op.amount = 500111000
        op.destination_account = stellar.address_to_public_key("GBOVKZBEM2YYLOCDCUXJ4IMRKHN4LCJAE7WEAEA2KF562XFAGDBOB64V")

        tx = self._create_msg()

        response = self.client.stellar_sign_transaction(tx, [op], self.get_address_n(),self.get_network_passphrase())

        assert b64encode(response.signature) == b'pDc6ghKCLNoYbt3h4eBw+533237m0BB0Jp/d/TxJCA83mF3o5Fr4l5vwAWBR62hdTWAP9MhVluY0cd5i54UwDg=='

    def test_sign_tx_payment_op_custom_asset1(self):
        """Custom asset payment (code length 1) of 50.0111 X to GBOVKZBEM2YYLOCDCUXJ4IMRKHN4LCJAE7WEAEA2KF562XFAGDBOB64V"""
        self.setup_mnemonic_nopin_nopassphrase()

        op = proto.StellarPaymentOp()
        op.amount = 500111000
        op.destination_account = stellar.address_to_public_key("GBOVKZBEM2YYLOCDCUXJ4IMRKHN4LCJAE7WEAEA2KF562XFAGDBOB64V")

        op.asset = proto.StellarAssetType(1, "X", stellar.address_to_public_key("GAUYJFQCYIHFQNS7CI6BFWD2DSSFKDIQZUQ3BLQODDKE4PSW7VVBKENC"))

        tx = self._create_msg()

        response = self.client.stellar_sign_transaction(tx, [op], self.get_address_n(), self.get_network_passphrase())

        assert b64encode(response.signature) == b'ArZydOtXU2whoRuSjJLFIWPSIsq3AbsncJZ+THF24CRSriVWw5Fy/dHrDlUOu4fzU28I6osDMeI39aWezg5tDw=='

    def test_sign_tx_payment_op_custom_asset12(self):
        """Custom asset payment (code length 12)of 50.0111 X to GBOVKZBEM2YYLOCDCUXJ4IMRKHN4LCJAE7WEAEA2KF562XFAGDBOB64V"""
        self.setup_mnemonic_nopin_nopassphrase()

        op = proto.StellarPaymentOp()
        op.amount = 500111000
        op.destination_account = stellar.address_to_public_key("GBOVKZBEM2YYLOCDCUXJ4IMRKHN4LCJAE7WEAEA2KF562XFAGDBOB64V")

        op.asset = proto.StellarAssetType(2, "ABCDEFGHIJKL", stellar.address_to_public_key("GAUYJFQCYIHFQNS7CI6BFWD2DSSFKDIQZUQ3BLQODDKE4PSW7VVBKENC"))

        tx = self._create_msg()

        response = self.client.stellar_sign_transaction(tx, [op], self.get_address_n(), self.get_network_passphrase())

        assert b64encode(response.signature) == b'QZIP4XKPfe4OpZtuJiyrMZBX9YBzvGpHGcngdgFfHn2kcdONreF384/pCF80xfEnGm8grKaoOnUEKxqcMKvxAA=='


    def _create_msg(self) -> proto.StellarSignTx:
        tx = proto.StellarSignTx()
        tx.protocol_version = 1
        tx.source_account = unhexlify('15d648bfe4d36f196cfb5735ffd8ca54cd4b8233f743f22449de7cf301cdb469')
        tx.fee = 100
        tx.sequence_number = 0x100000000
        tx.memo_type = 0
        return tx
