import time

from indy import anoncreds, crypto, did, ledger, pool, wallet

import json
import logging
from typing import Optional

from indy.error import ErrorCode, IndyError

from utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# wallet configs ---------------------------
steward_wallet = []
steward_wallet_config = {"id": "sovrin_steward_wallet"}
steward_wallet_credentials = {"key": "steward_wallet_key"}

minter_wallet = []
minter_wallet_config = {"id": "minter_wallet"}
minter_wallet_credentials = {"key": "minter_wallet_key"}

government_wallet = []
government_wallet_config = {"id": "government_wallet"}
government_wallet_credentials = {"key": "government_wallet_key"}

faber_wallet = []
faber_wallet_config = {"id": "faber_wallet"}
faber_wallet_credentials = {"key": "faber_wallet_key"}

acme_wallet = []
acme_wallet_config = {"id": "acme_wallet"}
acme_wallet_credentials = {"key": "acme_wallet_key"}

thrift_wallet = [] 
thrift_wallet_config = {"id": " thrift_wallet"}
thrift_wallet_credentials = {"key": "thrift_wallet_key"}

alice_wallet = []
alice_wallet_config = {"id": " alice_wallet"}
alice_wallet_credentials = {"key": "alice_wallet_key"}
# wallet configs ---------------------------

async def run():
    logger.info("Clean Up -> started")

    pool_name = 'pool1'
    logger.info("Open Pool Ledger: {}".format(pool_name))
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)

    try:
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    
    pool_handle = ""
    try:
        pool_handle = await pool.open_pool_ledger(pool_name, None)
    except IndyError as ex:
        pass
    
    for wallet_handle,config,credentials in [\
                                (steward_wallet, steward_wallet_config, steward_wallet_credentials),\
                                (minter_wallet, minter_wallet_config, minter_wallet_credentials),\
                                (government_wallet, government_wallet_config, government_wallet_credentials),\
                                (faber_wallet, faber_wallet_config, faber_wallet_credentials),\
                                (acme_wallet, acme_wallet_config, acme_wallet_credentials),\
                                (thrift_wallet, thrift_wallet_config, thrift_wallet_credentials),\
                                (alice_wallet, alice_wallet_config, alice_wallet_credentials),\
                                ]:  
        try:
            await wallet.create_wallet(json.dumps(config), json.dumps(credentials))
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass  
        finally:
            wallet_handle.append( await wallet.open_wallet(json.dumps(config), json.dumps(credentials) ))

    for wallet_handle,config,credentials in [\
                            (steward_wallet, steward_wallet_config, steward_wallet_credentials),\
                            (minter_wallet, minter_wallet_config, minter_wallet_credentials),\
                            (government_wallet, government_wallet_config, government_wallet_credentials),\
                            (faber_wallet, faber_wallet_config, faber_wallet_credentials),\
                            (acme_wallet, acme_wallet_config, acme_wallet_credentials),\
                            (thrift_wallet, thrift_wallet_config, thrift_wallet_credentials),\
                            (alice_wallet, alice_wallet_config, alice_wallet_credentials),\
                            ]:  
        try:
            logger.info("\"{}\" -> Close and Delete wallet ".format(config["id"]))
            await wallet.close_wallet(wallet_handle[0])
            await wallet.delete_wallet(json.dumps(config), json.dumps(credentials))
        except IndyError as ex:
            pass

    logger.info("Clean Up -> Finished")

if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)  # FIXME waiting for libindy thread complete
