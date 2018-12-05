import time

from indy import anoncreds, crypto, did, ledger, pool, wallet, payment

import json
import logging
from typing import Optional

from indy.error import ErrorCode, IndyError

import string
import random
import ctypes
import asyncio

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# wallet configs ---------------------------
minter_dids = ["000000000000000000000000Trustee1","000000000000000000000000Trustee2","000000000000000000000000Trustee3"]
minter_wallet = []
minter_wallet_config = {"id": "minter_wallet"}
minter_wallet_credentials = {"key": "minter_wallet_key"}
# wallet configs ---------------------------

async def run():
  
    await pool.set_protocol_version(2)

    #pool connection

    pool_name = "pool1" #------------------------------------------------------change-me----------------------------------------------------------

    libsovtoken = ctypes.CDLL('/c/Users/burdettadam/Documents/GitHub/libsovtoken/libsovtoken/target/debug/libsovtoken.so') #------------change-me------
    libsovtoken.sovtoken_init()

    pool_handle = await pool.open_pool_ledger(pool_name, None)  

    await create_wallet(minter_wallet,minter_wallet_config,minter_wallet_credentials)

    (trustee1_did, trustee1_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee1'})) # dids for trustees 
    (trustee2_did, trustee2_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee2'}))
    (trustee3_did, trustee3_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee3'}))

    nym_req_1 = await ledger.build_nym_request(trustee1_did, trustee2_did, trustee2_key, None, "TRUSTEE")
    await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, nym_req_1)

    get_nym_req = await ledger.build_get_nym_request(trustee1_did,trustee2_did)
    response = await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, get_nym_req)
    logger.info(" get nym response: {}".format(json.loads(response)["result"]["data"]))

    logger.info("=== Set fees ==")
    ''' txn codes 
    DOMAIN LEDGER
        
        NYM, 1
        ATTRIB, 100
        SCHEMA, 101
        CRED_DEF, 102
        POOL_UPGRADE, 109 ???

        REVOC_REG_DEF, 113
        REVOC_REG_ENTRY, 114
    PAYMENT LEDGER
        MINTING, 10000
        XFER_PUBLIC, 10001
        GET_UTXO, 10002
        SET_FEES, 20000
        GET_FEES, 20001

    '''
    set_fees_req = await payment.build_set_txn_fees_req(minter_wallet[0],trustee1_did,"sov", json.dumps({   
        "10001":1000000000000,
                                                                                                        } ))
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee1_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee2_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee3_did, set_fees_req)

    await ledger.sign_and_submit_request(pool_handle,minter_wallet[0] , trustee1_did, set_fees_req)
    
    req = await payment.build_get_txn_fees_req(minter_wallet[0], trustee1_did, "sov") # check fees are set
    resp = await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, req)
    logger.info(" ledger fees: {}".format(json.loads(resp)["result"]["fees"]))

    try:
        await wallet.close_wallet(minter_wallet[0])
        await wallet.delete_wallet(json.dumps(minter_wallet_config), json.dumps(minter_wallet_credentials))
    except IndyError as ex:
        pass

    logger.info("Close pool")
    await pool.close_pool_ledger(pool_handle)

async def create_wallet(wallet_handle,config,credentials):
    logger.info("\"Create Wallet\" -> Create Wallet and payment address for {}".format(config["id"]))
    try:
        await wallet.delete_wallet(json.dumps(config), json.dumps(credentials))
    except IndyError as ex:
        pass
    finally:
        await wallet.create_wallet(json.dumps(config), json.dumps(credentials))
        wallet_handle.append( await wallet.open_wallet(json.dumps(config), json.dumps(credentials) )) #open
        wallet_handle.append( await payment.create_payment_address(wallet_handle[0], "sov", json.dumps({"seed": ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))})) )

async def get_payment_source(pool_handle, wallet_handle, did, address ):
    (req,payment_method ) = await payment.build_get_payment_sources_request(wallet_handle, did, address)
    resp = await ledger.submit_request(pool_handle, req)
    sources_info_as_json = await payment.parse_get_payment_sources_response(payment_method, resp)
    return sources_info_as_json


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())
    time.sleep(1)  # FIXME waiting for libindy thread complete