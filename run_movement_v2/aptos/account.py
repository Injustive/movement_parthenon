from aptos_sdk.account import Account


class AptosAccount:
    def __init__(self, pk):
        self.__pk = pk
        self.account = Account.load_key(self.__pk)

    @property
    def aptos_public_key(self):
        public_key = self.account.public_key()
        return public_key

    @property
    def aptos_address(self):
        address = self.account.address()
        return address

    def get_signed_code(self, msg: str):
        message_bytes = msg.encode('utf-8')
        signature = self.account.sign(message_bytes)
        return signature
