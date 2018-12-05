import time

from indy import anoncreds, crypto, did, ledger, pool, wallet, payment, blob_storage

import json
import logging
from typing import Optional

from indy.error import ErrorCode, IndyError

from utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION
from pathlib import Path
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
    logger.info("Getting started -> started")

    logger.info("==============================")
    logger.info("=== Connecting to pool ==")
    logger.info("------------------------------")

    pool_name = "pool1"

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)

    # Set libsovtoken()
    libsovtoken = ctypes.CDLL('/c/Users/burdettadam/Documents/GitHub/libsovtoken/libsovtoken/target/debug/libsovtoken.so')
    libsovtoken.sovtoken_init()

    pool_handle = await pool.open_pool_ledger(pool_name, None) 

    logger.info("==============================")
    logger.info("=== Creating wallets for Steward, Minter, Faber, Acme, Thrift and Government with a payment address  ==")
    logger.info("------------------------------")
    # attempting to use multiple processes...... 
    loop = asyncio.get_event_loop()
    
    tasks= []
    for wallet_handle,config,credentials in [\
                                (steward_wallet, steward_wallet_config, steward_wallet_credentials),\
                                (minter_wallet, minter_wallet_config, minter_wallet_credentials),
                                ]:
        tasks.append(loop.create_task(create_wallet(wallet_handle,config,credentials)))
    await asyncio.wait(tasks)
    # reset fees 
    
    
    logger.info("\"Sovrin Steward\" -> Create and store in Wallet DID from seed")
    steward_did_info = {'seed': '000000000000000000000000Steward1'} # this generates the same keys used in the genisis file 
    (steward_did, steward_key) = await did.create_and_store_my_did(steward_wallet[0], json.dumps(steward_did_info))

    logger.info("==============================")
    logger.info("=== Creating tokens  ==")
    logger.info("------------------------------")
    
    logger.info("\"minter\" -> Create and store in Wallet DID from truestee1 seed")
    (trustee1_did, trustee1_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee1'}))
    (trustee2_did, trustee2_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee2'}))
    (trustee3_did, trustee3_key) = await did.create_and_store_my_did(minter_wallet[0], json.dumps({'seed':'000000000000000000000000Trustee3'}))

    logger.info("\"minter\" -> Nym truestee 1 & 2")
    nym_req_1 = await ledger.build_nym_request(trustee1_did, trustee2_did, trustee2_key, None, "TRUSTEE")
    await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, nym_req_1)

    nym_req_2 = await ledger.build_nym_request(trustee1_did, trustee3_did, trustee3_key, None, "TRUSTEE")
    await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, nym_req_2)
    
    
    logger.info("\"minter\" -> build mint req")
    req, payment_method = await payment.build_mint_req(minter_wallet[0], trustee1_did, json.dumps([{"recipient": 'pay:sov:2Hjhzp3yjLWwRtd8mFKoaJLWpnGEkCHRgc5LFUdmU3XtZGqWXt', "amount": 1999999999999999999}]), None)

    logger.info("\"minter\" -> sign mint req") # requires 3 trustees signitures 
    req = await ledger.multi_sign_request(minter_wallet[0], trustee1_did, req)
    req = await ledger.multi_sign_request(minter_wallet[0], trustee2_did, req)
    req = await ledger.multi_sign_request(minter_wallet[0], trustee3_did, req)

    logger.info("\"minter\" -> submit mint request")

    resp = await ledger.submit_request(pool_handle, req)

    logger.info(resp)

    logger.info("==============================")
    for wallet_handle,config,credentials in [\
                            (steward_wallet[0], steward_wallet_config, steward_wallet_credentials),\
                            (minter_wallet[0], minter_wallet_config, minter_wallet_credentials),
                            ]:  
        try:
            logger.info("\"{}\" -> Close and Delete wallet ".format(config["id"]))
            await wallet.close_wallet(wallet_handle)
            await wallet.delete_wallet(json.dumps(config), json.dumps(credentials))
        except IndyError as ex:
            pass

    logger.info("Close pool")
    #logger.info("Close and Delete pool")
    await pool.close_pool_ledger(pool_handle)
    #await pool.delete_pool_ledger_config(pool_name)


async def build_wallet( to_wallet_config: str, to_wallet_credentials: str):
    try:
        await wallet.create_wallet(to_wallet_config, to_wallet_credentials)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    to_wallet = await wallet.open_wallet(to_wallet_config, to_wallet_credentials)
    return to_wallet

async def get_verinym(pool_handle, _from, from_wallet, from_did,
                      to, to_wallet, role):
    logger.info("\"{}\" -> Create and store in Wallet \"{}\" new DID".format(to, to))
    (to_did, to_key) = await did.create_and_store_my_did(to_wallet, "{}")

    did_info_json = json.dumps({
        'did': to_did,
        'verkey': to_key
    })

    logger.info("\"{}\" -> Send \"{} DID info\" to {}".format(to, to, _from))

    authdecrypted_did_info = json.loads(did_info_json)

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} DID\" with {} Role".format(_from, to, role))
    await send_nym(pool_handle, from_wallet, from_did, authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'], role)
    return to_did

async def get_verinym_with_fee(pool_handle, _from, from_wallet, from_did, #TODO, write this method.
                      to, to_wallet, role):
    logger.info("\"{}\" -> Create and store in Wallet \"{}\" new DID".format(to, to))
    (to_did, to_key) = await did.create_and_store_my_did(to_wallet, "{}")

    did_info_json = json.dumps({
        'did': to_did,
        'verkey': to_key
    })

    logger.info("\"{}\" -> Send \"{} DID info\" to {}".format(to, to, _from))

    authdecrypted_did_info = json.loads(did_info_json)

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} DID\" with {} Role".format(_from, to, role))
    await send_nym(pool_handle, from_wallet, from_did, authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'], role)
    return to_did

async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)

async def send_nym_with_fee(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)

async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)

async def send_cred_def_with_fees(pool_handle, wallet, tx, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    get_schema_response = await send_request_with_fees(pool_handle, wallet,tx, cred_def_request, _did)

async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)

async def get_schema_with_fees(pool_handle, wallet, tx, _did, schema_id):
    inputs_json  = json.dumps([wallet[2]])
    outputs_json = json.dumps([ {"recipient" : wallet[1], "amount": wallet[3] - tx}])
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await send_request_with_fees(pool_handle, wallet, tx, get_schema_request, _did)
    logger.info("\"{}\"".format(get_schema_response))
    return get_schema_response
    #return await ledger.parse_get_schema_response(get_schema_response)

async def send_request_with_fees(pool_handle, wallet,tx, request , _did):
    inputs_json  = json.dumps([wallet[2]])
    outputs_json = json.dumps([ {"recipient" : wallet[1], "amount": wallet[3] - tx}])
    req_signed = await ledger.sign_request(wallet[0], _did, request)
    (req_with_fees, pm) = await payment.add_request_fees(wallet[0], _did, req_signed,inputs_json,outputs_json, None )
    response = await ledger.submit_request(pool_handle, req_with_fees)
    logger.info("submit_request with fees:")
    logger.info(response)
    return await payment.parse_response_with_fees(pm, response)


async def get_cred_def(pool_handle, _did, schema_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, schema_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
                                                #blob_storage_reader_handle,rev_reg_def_json,rev_reg_delta_json,rev_id):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        '''if 'rev_reg_seq_no' in item:
            # Create Revocation States
            timestamp = 100
            rev_state_json = await anoncreds.create_revocation_state(blob_storage_reader_handle, rev_reg_def_json,
                                                             rev_reg_delta_json, timestamp, rev_id)
            rev_states[rev_id] = {timestamp: json.loads(rev_state_json)}'''

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Get Revocation Definitions and Revocation Registries

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def auth_decrypt(wallet_handle, key, message):
    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
    decrypted_message_json = decrypted_message_json.decode("utf-8")
    decrypted_message = json.loads(decrypted_message_json)
    return from_verkey, decrypted_message_json, decrypted_message

async def get_vk_by_seed_and_did(seed, did_to_resolve):
    try:
        _, vk = await did.create_and_store_my_did(wallet_id, json.dumps({"seed": seed}))
    except:
        vk = await did.key_for_local_did(wallet_id, did_to_resolve)
    return vk

async def add_utxo_wallet(pool_handle,wallet,_did):
    sources_info_as_json = await get_payment_source(pool_handle, wallet[0], _did, wallet[1] )
    wallet.append(json.loads(sources_info_as_json)[0]["source"])
    wallet.append(json.loads(sources_info_as_json)[0]["amount"])

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
    ##########################resp = await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, req)# does not work why??
    resp = await ledger.submit_request(pool_handle, req)
    sources_info_as_json = await payment.parse_get_payment_sources_response(payment_method, resp)
    return sources_info_as_json

if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)  # FIXME waiting for libindy thread complete
