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
steward_dids = ["000000000000000000000000Steward1"]
steward_wallet = []
steward_wallet_config = {"id": "sovrin_steward_wallet"}
steward_wallet_credentials = {"key": "steward_wallet_key"}

minter_dids = ["000000000000000000000000Trustee1","000000000000000000000000Trustee2","000000000000000000000000Trustee3"]
minter_wallet = []
minter_wallet_config = {"id": "minter_wallet"}
minter_wallet_credentials = {"key": "minter_wallet_key"}
# wallet configs ---------------------------

async def run():

    logger.info("==============================")
    logger.info("=== Connecting to pool ==")
    logger.info("------------------------------")

    pool_name = "rLJJ41TslS" #------------------------------------------------------change-me----------------------------------------------------------
  
    await pool.set_protocol_version(2)

    # Set libsovtoken()
    libsovtoken = ctypes.CDLL('/c/Users/burdettadam/Documents/GitHub/libsovtoken/libsovtoken/target/debug/libsovtoken.so') #------------change-me------
    libsovtoken.sovtoken_init()

    pool_handle = await pool.open_pool_ledger(pool_name, None) 

    logger.info("=== Creating wallets for Steward, and Minter with a payment address  ==")
    # attempting to use multiple processes......but does not work because of sqlite
    loop = asyncio.get_event_loop()
    
    tasks= []
    for wallet_handle,config,credentials in [\
                                (steward_wallet, steward_wallet_config, steward_wallet_credentials),\
                                (minter_wallet, minter_wallet_config, minter_wallet_credentials)
                                ]:
        tasks.append(loop.create_task(create_wallet(wallet_handle,config,credentials)))
    await asyncio.wait(tasks)
    
    
    logger.info("\"Sovrin Steward\" -> Create and store in Wallet DID from seed")
    steward_did_info = {'seed': '000000000000000000000000Steward1'} # this generates the same keys used in the genisis file 
    (steward_did, steward_key) = await did.create_and_store_my_did(steward_wallet[0], json.dumps(steward_did_info))

    logger.info("=== Creating tokens  ==")
    
    logger.info("\"minter\" -> Create and store in Wallet DID from truestee1 seed")
    (trustee1_did, trustee1_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee1'}))
    (trustee2_did, trustee2_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee2'}))
    (trustee3_did, trustee3_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee3'}))


    logger.info("\"minter\" -> Create and store in Wallet DID from truestee1 seed")
    nym_req_1 = await ledger.build_nym_request(trustee1_did, trustee2_did, trustee2_key, None, "TRUSTEE")
    await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, nym_req_1)

    nym_req_2 = await ledger.build_nym_request(trustee1_did, trustee3_did, trustee3_key, None, "TRUSTEE")
    await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, nym_req_2)
    
    sources_info_as_json = await get_payment_source(pool_handle, minter_wallet[0], trustee1_did, minter_wallet[1] )
    logger.info("\"minter\" -> payment sources response before minting: {}, payment type: {}".format(sources_info_as_json,"sov"))
    
    logger.info("\"minter\" -> build mint req")
    req, payment_method = await payment.build_mint_req(minter_wallet[0], trustee1_did, json.dumps([{"recipient": minter_wallet[1], "amount": 199999999999999999}]), None)

    logger.info("\"minter\" -> sign mint req") # requires 3 trustees signitures 
    req = await ledger.multi_sign_request(minter_wallet[0], trustee1_did, req)
    req = await ledger.multi_sign_request(minter_wallet[0], trustee2_did, req)
    req = await ledger.multi_sign_request(minter_wallet[0], trustee3_did, req)

    logger.info("\"minter\" -> submit mint request")
    resp = await ledger.submit_request(pool_handle, req)

    # look at address for tokens
    sources_info_as_json = await get_payment_source(pool_handle, minter_wallet[0], trustee1_did, minter_wallet[1] )
    logger.info("\"minter\" -> payment sources response after minting: {}, payment type: {}".format(sources_info_as_json,payment_method))

    minter_wallet.append(json.loads(sources_info_as_json)[0]["source"])
    minter_wallet.append(json.loads(sources_info_as_json)[0]["amount"])
    tx_fee = 0

    # invalid transfer

    logger.info("\n\n=== invalid token transfer ===\n")

    inputs_json  = json.dumps([minter_wallet[2]])
    outputs_json = json.dumps([ { "recipient" : steward_wallet[1]   , "amount": 10000000 }]) #<----------------- no remainder address
    (payment_req_json,payment_method)  = await payment.build_payment_req(minter_wallet[0],trustee1_did,inputs_json,outputs_json,None)
    await ledger.sign_and_submit_request(pool_handle,minter_wallet[0],trustee1_did,payment_req_json)
    
    sources_info_as_json = await get_payment_source(pool_handle, minter_wallet[0], trustee1_did, minter_wallet[1] )
    logger.info("\"minter\" -> payment sources response for minter: {}, payment type: {}".format(sources_info_as_json,payment_method))
    sources_info_as_json = await get_payment_source(pool_handle, steward_wallet[0], steward_did, steward_wallet[1] )
    logger.info("\"steward\" -> payment sources response for steward: {}, payment type: {}".format(sources_info_as_json,payment_method))

    # valid transfer
    
    logger.info("\n=== valid token transfer ===\n")

    inputs_json  = json.dumps([minter_wallet[2]])
    outputs_json = json.dumps([ {"recipient" : minter_wallet[1]   , "amount":int(minter_wallet[3]) - 10000000 - tx_fee } ,{"recipient" : steward_wallet[1]   , "amount": 10000000 }]) #<---------- with remainder address
    (payment_req_json,payment_method)  = await payment.build_payment_req(minter_wallet[0],trustee1_did,inputs_json,outputs_json,None)
    await ledger.sign_and_submit_request(pool_handle,minter_wallet[0],trustee1_did,payment_req_json)

    sources_info_as_json = await get_payment_source(pool_handle, minter_wallet[0], trustee1_did, minter_wallet[1] )
    logger.info("\"minter\" -> payment sources response for minter: {}, payment type: {}".format(sources_info_as_json,payment_method))
    sources_info_as_json = await get_payment_source(pool_handle, steward_wallet[0], steward_did, steward_wallet[1] )
    logger.info("\"steward\" -> payment sources response for steward: {}, payment type: {}".format(sources_info_as_json,payment_method))

    logger.info("==============================")
    for wallet_handle,config,credentials in [\
                            (steward_wallet, steward_wallet_config, steward_wallet_credentials),\
                            (minter_wallet, minter_wallet_config, minter_wallet_credentials) ]:  
        try:
            logger.info("\"{}\" -> Close and Delete wallet ".format(config["id"]))
            await wallet.close_wallet(wallet_handle[0])
            await wallet.delete_wallet(json.dumps(config), json.dumps(credentials))
        except IndyError as ex:
            pass

    logger.info("Close pool")
    await pool.close_pool_ledger(pool_handle)

    logger.info("Getting started -> done")

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