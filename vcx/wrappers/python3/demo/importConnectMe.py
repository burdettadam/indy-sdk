import argparse, os, sys
import json
import base64
import asyncio


from Crypto.Protocol.KDF import PBKDF2
from vcx.api.wallet import Wallet as vcxWallet

# check arguments
parser = argparse.ArgumentParser()
parser.add_argument("file", help="the wallet we want to import")
parser.add_argument("passphrase", help="connect.me passphrase from backup")
parser.add_argument("salt", help="connect.me salt from backup")
parser.add_argument("walletName", help="wallet name")
parser.add_argument("walletKey", help="wallet key")

args = parser.parse_args()
print(args.passphrase)
print(args.salt)

#https://github.com/tectiv3/react-native-aes/blob/e1f7de2d37242339f425814f592265ce00c50c96/android/src/main/java/com/tectiv3/aes/RCTAes.java#L48
key = PBKDF2(args.passphrase, args.salt.encode(), 5000, 64)
#key = kdf[:32]
#key_mac = kdf[32:]
print(base64.b64encode(key).decode("utf-8"))

config = json.dumps({
    "wallet_name": args.walletName,
    "wallet_key": args.walletKey,
    "exported_wallet_path": args.file,
    "backup_key": base64.b64encode(key).decode("utf-8"),
  })

print(config)

loop = asyncio.get_event_loop()
loop.run_until_complete(
    vcxWallet.import_wallet(config)
)

