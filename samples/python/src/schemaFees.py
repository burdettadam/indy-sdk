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

    pool_name = "rLJJ41TslS" #------------------------------------------------------change-me----------------------------------------------------------

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

    # MINT SOME TOKENS
    sources_info_as_json = await get_payment_source(pool_handle, minter_wallet[0], trustee1_did, minter_wallet[1] )
    req, payment_method = await payment.build_mint_req(minter_wallet[0], trustee1_did, json.dumps([{"recipient": minter_wallet[1], "amount": 199999999999999999}]), None)
    req = await ledger.multi_sign_request(minter_wallet[0], trustee1_did, req)
    req = await ledger.multi_sign_request(minter_wallet[0], trustee2_did, req)
    req = await ledger.multi_sign_request(minter_wallet[0], trustee3_did, req)
    resp = await ledger.submit_request(pool_handle, req)

    # look at address for tokens
    sources_info_as_json = await get_payment_source(pool_handle, minter_wallet[0], trustee1_did, minter_wallet[1] )
    logger.info("payment sources response after minting: {}, payment type: {}".format(sources_info_as_json,payment_method))

    minter_wallet.append(json.loads(sources_info_as_json)[0]["source"])
    minter_wallet.append(json.loads(sources_info_as_json)[0]["amount"])
    tx_fee = 12
    

    logger.info("=== Set fees ==")

    set_fees_req = await payment.build_set_txn_fees_req(minter_wallet[0],trustee1_did,"sov", json.dumps( {  "1":20,
                                                                                                "100":30,"101":10 } ))
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee1_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee2_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee3_did, set_fees_req)

    await ledger.sign_and_submit_request(pool_handle,minter_wallet[0] , trustee1_did, set_fees_req)
    
    req = await payment.build_get_txn_fees_req(minter_wallet[0], trustee1_did, "sov") # check fees are set
    resp = await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, req)
    logger.info(" ledger fees: {}".format(json.loads(resp)["result"]["fees"]))
    
    #(trustee4_did, trustee4_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee4'}))
    logger.info("create schema")
    (job_certificate_schema_id, job_certificate_schema) = \
        await anoncreds.issuer_create_schema(trustee1_did, 'Job-Certificate', '2.5',
                                             json.dumps(['first_name', 'last_name', 'salary', 'employee_status',
                                                         'experience']))
    logger.info("send schema")
    result = await send_schema(pool_handle, minter_wallet[0], trustee1_did, job_certificate_schema)
    logger.info(result)
    # SCHEMA WITH FEES 
    '''inputs_json  = json.dumps([minter_wallet[2]])
    outputs_json = json.dumps([ {"recipient" : minter_wallet[1]   , "amount":int(minter_wallet[3]) - 0 - tx_fee }])

    (job_certificate_schema_id, job_certificate_schema) = \
        await anoncreds.issuer_create_schema(trustee4_did, 'Job-Certificate', '1.6',
                                             json.dumps(['first_name', 'last_name', 'salary', 'employee_status',
                                                         'experience']))
    schema_request = await ledger.build_schema_request(trustee4_did, job_certificate_schema)
    logger.info("sign request:")
    req_signed = await ledger.sign_request(minter_wallet[0], trustee1_did, schema_request)
    logger.info("add request fees:")
    (req_with_fees, pm) = await payment.add_request_fees(minter_wallet[0], trustee4_did, req_signed, inputs_json, outputs_json, None ) # SPEND TOKENS
    logger.info("submit fees:")
    resp = await ledger.submit_request(pool_handle, req_with_fees)
    logger.info(resp)
    parsed_resp = await payment.parse_response_with_fees(pm, resp)
    logger.info("request fees response: {}".format(parsed_resp))
    '''

    '''logger.info("=== Set fees to zero ==")

    set_fees_req = await payment.build_set_txn_fees_req(minter_wallet[0],trustee1_did,"sov", json.dumps( { "101":0 } ))
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee1_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee2_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee3_did, set_fees_req)
    await ledger.sign_and_submit_request(pool_handle,minter_wallet[0] , trustee1_did, set_fees_req)
    '''
    logger.info("get schema")

    (_, transcript_schema) = await get_schema(pool_handle, trustee1_did, job_certificate_schema_id)

    logger.info("get scheme response: {}".format(json.loads(transcript_schema)))

    #sources_info_as_json = await get_payment_source(pool_handle, minter_wallet[0], trustee1_did, minter_wallet[1] )
    #logger.info(" payment sources response after nym tx: {}, payment type: {}".format(sources_info_as_json,payment_method))

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

async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)

async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())
    time.sleep(1)  # FIXME waiting for libindy thread complete