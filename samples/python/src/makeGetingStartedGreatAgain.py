import time

from indy import anoncreds, crypto, did, ledger, pool, wallet, payment

import json
import logging
from typing import Optional

from indy.error import ErrorCode, IndyError

from utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION

import string
import random
import ctypes
import asyncio

#from vcx.api.wallet import Wallet as vcxwallet // vcx is not ready to be used.
#from vcx.api.utils import vcx_ledger_get_fees
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# wallet configs ---------------------------
steward_dids = ["000000000000000000000000Steward1"]
steward_wallet = []
steward_wallet_config = {"id": "sovrin_steward_wallet"}
steward_wallet_credentials = {"key": "steward_wallet_key"}


minter_dids = ["000000000000000000000000Trustee" + str(i +1) for i in range(0,2) ]
minter_wallet = []
minter_wallet_config = {"id": "minter_wallet"}
minter_wallet_credentials = {"key": "minter_wallet_key"}

government_dids = []
government_wallet = []
government_wallet_config = {"id": "government_wallet"}
government_wallet_credentials = {"key": "government_wallet_key"}

faber_dids = []
faber_wallet = []
faber_wallet_config = {"id": "faber_wallet"}
faber_wallet_credentials = {"key": "faber_wallet_key"}

acme_did = []
acme_wallet = []
acme_wallet_config = {"id": "acme_wallet"}
acme_wallet_credentials = {"key": "acme_wallet_key"}

thrift_dids = []
thrift_wallet = []
thrift_wallet_config = {"id": " thrift_wallet"}
thrift_wallet_credentials = {"key": "thrift_wallet_key"}

alice_dids = []
alice_wallet = []
alice_wallet_config = {"id": " alice_wallet"}
alice_wallet_credentials = {"key": "alice_wallet_key"}
# wallet configs ---------------------------
class Wallet:
    def __init__(self, config, creds ,dids=[], wallet=[]):
        self.dids = dids
        self.wallet = wallet
        self.config = config
        self.creds = creds

all_wallets = [
                Wallet( steward_wallet_config, steward_wallet_credentials,      [], steward_wallet ),
                Wallet( minter_wallet_config, minter_wallet_credentials,        [], minter_wallet),
                Wallet( government_wallet_config, government_wallet_credentials,[], government_wallet),
                Wallet( faber_wallet_config, faber_wallet_credentials,          [], faber_wallet),
                Wallet( acme_wallet_config, acme_wallet_credentials,            [], acme_wallet),
                Wallet( thrift_wallet_config, thrift_wallet_credentials,        [], thrift_wallet),
                Wallet( alice_wallet_config, alice_wallet_credentials,          [], alice_wallet)]


async def run():
    logger.info("Getting started -> started")

    logger.info("==============================")
    logger.info("=== Connecting to pool ==")
    logger.info("------------------------------")

    pool_name = "rLJJ41TslS"
    '''logger.info("Open Pool Ledger: {}".format(pool_name))
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})
    '''
    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)

    # Set libsovtoken()
    libsovtoken = ctypes.CDLL('/c/Users/burdettadam/Documents/GitHub/libsovtoken/libsovtoken/target/debug/libsovtoken.so')
    libsovtoken.sovtoken_init()

    '''try:
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError or ex.error_code == ErrorCode.CommonInvalidState:
            pass
        pass'''
    pool_handle = await pool.open_pool_ledger(pool_name, None)
    '''try:
        pool_handle = await pool.open_pool_ledger(pool_name, None)
    except IndyError as ex:
        pass'''

    logger.info("==============================")
    logger.info("=== Creating wallets for Steward, Minter, Faber, Acme, Thrift and Government with a payment address  ==")
    logger.info("------------------------------")
    # attempting to use multiple processes......
    loop = asyncio.get_event_loop()

    tasks= [loop.create_task(create_wallet(wallet.wallet,wallet.config,wallet.creds)) for wallet in all_wallets]
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


    logger.info("\"Reset Ledger Fees\"")
    set_fees_req = await payment.build_set_txn_fees_req(minter_wallet[0],trustee1_did,"sov", json.dumps({
                                                                                                "1":0,
                                                                                                "100":0,
                                                                                                "101":0,
                                                                                                "102":0,
                                                                                                "113":0,
                                                                                                "114":0,
                                                                                                "10001":0
                                                                                                }))
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee1_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee2_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee3_did, set_fees_req)

    await ledger.sign_and_submit_request(pool_handle,minter_wallet[0] , trustee1_did, set_fees_req)


    logger.info("\"minter\" -> Create and store in Wallet DID from truestee1 seed")
    nym_req_1 = await ledger.build_nym_request(trustee1_did, trustee2_did, trustee2_key, None, "TRUSTEE")
    await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, nym_req_1)

    nym_req_2 = await ledger.build_nym_request(trustee1_did, trustee3_did, trustee3_key, None, "TRUSTEE")
    await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, nym_req_2)


    #logger.info("\"minter\" -> mint address: {}, seed: {}".format(minter_wallet[1],seed))

    logger.info("\"minter\" -> build mint req")
    req, payment_method = await payment.build_mint_req(minter_wallet[0], trustee1_did, json.dumps([{"recipient": minter_wallet[1], "amount": 1999999999999999999}]), None)

    logger.info("\"minter\" -> sign mint req") # requires 3 trustees signitures
    req = await ledger.multi_sign_request(minter_wallet[0], trustee1_did, req)
    req = await ledger.multi_sign_request(minter_wallet[0], trustee2_did, req)
    req = await ledger.multi_sign_request(minter_wallet[0], trustee3_did, req)

    logger.info("\"minter\" -> submit mint request")
    resp = await ledger.submit_request(pool_handle, req)

    # look at address for tokens
    sources_info_as_json = await get_payment_source(pool_handle, minter_wallet[0], trustee1_did, minter_wallet[1] )

    minter_wallet.append(json.loads(sources_info_as_json)[0]["source"])
    minter_wallet.append(json.loads(sources_info_as_json)[0]["amount"])

    logger.info("\"minter\" -> payment sources response: {}, payment type: {}".format(sources_info_as_json,payment_method))

    logger.info("==============================")
    logger.info("=== Set fees ==")
    logger.info("------------------------------")
    #req = await payment.build_get_txn_fees_req(minter_wallet[0], trustee1_did, "sov")
    #resp = await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, req)

    #logger.info("\"minter\" -> ledger fees: {}".format(resp))
    ''' txn codes
    DOMAIN LEDGER
        NYM, 1
        ATTRIB, 100
        SCHEMA, 101
        CRED_DEF, 102
        REVOC_REG_DEF, 113
        REVOC_REG_ENTRY, 114
    PAYMENT LEDGER
        XFER_PUBLIC, 10001

    '''
    set_fees_req = await payment.build_set_txn_fees_req(minter_wallet[0],trustee1_did,"sov", json.dumps({
                                                                                                "1":10,
                                                                                                "100":11,
                                                                                                "101":12,
                                                                                                "102":13,
                                                                                                "113":14,
                                                                                                "114":15,
                                                                                                "10001":2
                                                                                                }))
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee1_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee2_did, set_fees_req)
    set_fees_req = await ledger.multi_sign_request(minter_wallet[0], trustee3_did, set_fees_req)

    await ledger.sign_and_submit_request(pool_handle,minter_wallet[0] , trustee1_did, set_fees_req)

    #logger.info("\"minter\" -> ledger fees: {}".format(fees))
    #resp = await ledger.submit_request(pool_handle, set_fees_req)

    req = await payment.build_get_txn_fees_req(minter_wallet[0], trustee1_did, "sov")
    resp = await ledger.sign_and_submit_request(pool_handle, minter_wallet[0], trustee1_did, req)

    logger.info("\"minter\" -> ledger fees: {}".format(resp))

    logger.info("==============================")
    logger.info("== distribute tokens ==")
    logger.info("------------------------------")

    inputs_json  = json.dumps([minter_wallet[2]])
    outputs_json = json.dumps([ {"recipient" : minter_wallet[1], "amount": minter_wallet[3]-60000000 }, {"recipient" : steward_wallet[1]   , "amount": 10000000 },
                                                                                                        {"recipient" : government_wallet[1], "amount": 10000000 },
                                                                                                        {"recipient" : faber_wallet[1]     , "amount": 10000000 },
                                                                                                        {"recipient" : acme_wallet[1]      , "amount": 10000000 },
                                                                                                        {"recipient" : thrift_wallet[1]    , "amount": 10000000 },
                                                                                                        {"recipient" : alice_wallet[1]     , "amount": 10000000 }])
    (payment_req_json,payment_method)  = await payment.build_payment_req(minter_wallet[0],trustee1_did,inputs_json,outputs_json,None)
    await ledger.sign_and_submit_request(pool_handle,minter_wallet[0],trustee1_did,payment_req_json)

    '''transfer = 10000000
    for wallet_handle in [
                        steward_wallet,
                        government_wallet,
                        faber_wallet,
                        acme_wallet,
                        thrift_wallet,
                        alice_wallet]:
        (payment_req_json,payment_method)  = await payment.build_payment_req(   minter_wallet[0],
                                                                                trustee1_did,
                                                                                json.dumps([minter_wallet[2]]),
                                                                                json.dumps([ {"recipient" : wallet_handle[1], "amount": 10000000 },{"recipient" : minter_wallet[1], "amount": minter_wallet[3]-transfer }]),
                                                                                None)
        await ledger.sign_and_submit_request(pool_handle,minter_wallet[0],trustee1_did,payment_req_json)
        transfer += transfer'''


    sources_info_as_json = await get_payment_source(pool_handle, minter_wallet[0], trustee1_did, minter_wallet[1] )
    logger.info("\"minter\" -> payment sources response: {}, payment type: {}".format(sources_info_as_json,payment_method))
    sources_info_as_json = await get_payment_source(pool_handle, steward_wallet[0], steward_did, steward_wallet[1] )
    logger.info("\"minter\" -> payment sources response: {}, payment type: {}".format(sources_info_as_json,payment_method))


    logger.info("==============================")
    logger.info("=== Getting Trust Anchor credentials for Faber, Acme, Thrift and Government  ==")
    logger.info("------------------------------")


    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Government getting Verinym  ==")
    logger.info("------------------------------")

    government_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet[0], steward_did,
                                        "Government", government_wallet[0],
                                        'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Faber getting a Verinym  ==")
    logger.info("------------------------------")

    faber_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet[0], steward_did,
                                  "Faber", faber_wallet[0], 'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Acme getting a Verinym  ==")
    logger.info("------------------------------")

    acme_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet[0], steward_did,
                                 "Acme", acme_wallet[0], 'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Thrift getting a Verinym  ==")
    logger.info("------------------------------")

    thrift_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet[0], steward_did,
                                   "Thrift", thrift_wallet[0], 'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("=== Credential Schemas Setup ==")
    logger.info("------------------------------")

    logger.info("\"Government\" -> Create \"Job-Certificate\" Schema")
    (job_certificate_schema_id, job_certificate_schema) = \
        await anoncreds.issuer_create_schema(government_did, 'Job-Certificate', '0.2',
                                             json.dumps(['first_name', 'last_name', 'salary', 'employee_status',
                                                         'experience']))

    logger.info("\"Government\" -> Send \"Job-Certificate\" Schema to Ledger")
    await send_schema(pool_handle, government_wallet[0], government_did, job_certificate_schema)

    logger.info("\"Government\" -> Create \"Transcript\" Schema")
    (transcript_schema_id, transcript_schema) = \
        await anoncreds.issuer_create_schema(government_did, 'Transcript', '1.2',
                                             json.dumps(['first_name', 'last_name', 'degree', 'status',
                                                         'year', 'average', 'ssn']))
    logger.info("\"Government\" -> Send \"Transcript\" Schema to Ledger")
    await send_schema(pool_handle, government_wallet[0], government_did, transcript_schema)

    logger.info("==============================")
    logger.info("=== Faber Credential Definition Setup ==")
    logger.info("------------------------------")

    logger.info("\"Faber\" -> Get \"Transcript\" Schema from Ledger")
    # (_, transcript_schema) = await get_schema(pool_handle, faber_did, transcript_schema_id)
    (_, transcript_schema) = await get_schema_with_fees(pool_handle, faber_wallet[0], json.dumps([faber_wallet[2]]), json.dumps([{{"recipient" : faber_wallet[1], "amount": 10000000 }}]), faber_did, transcript_schema_id)
    logger.info("\"Faber\" -> Create and store in Wallet \"Faber Transcript\" Credential Definition")
    (faber_transcript_cred_def_id, faber_transcript_cred_def_json) = \
        await anoncreds.issuer_create_and_store_credential_def(faber_wallet[0], faber_did, transcript_schema,
                                                               'TAG1', 'CL', '{"support_revocation": false}')

    logger.info("\"Faber\" -> Send  \"Faber Transcript\" Credential Definition to Ledger")
    #----------------------------------------------------------------------------------------------------------------------------------------------------
    # Issuer prepare cred_def.
    #----------------------------------------------------------------------------------------------------------------------------------------------------
    cred_def_request = await ledger.build_cred_def_request(faber_did, faber_transcript_cred_def_json)
    #logger.info("cred_def_request "+ json.dumps(cred_def_request))
    #----------------------------------------------
    # Trust Anchor sends to ledger.
    #----------------------------------------------
    await ledger.sign_and_submit_request(pool_handle,faber_wallet[0] , faber_did, cred_def_request)
    #await ledger.sign_and_submit_request(pool_handle,government_wallet[0] , government_did, cred_def_request)
    #----------------------------------------------------------------------------------------------------------------------------------------------------
    #----------------------------------------------------------------------------------------------------------------------------------------------------

    logger.info("==============================")
    logger.info("=== Acme Credential Definition Setup ==")
    logger.info("------------------------------")

    logger.info("\"Acme\" -> Get from Ledger \"Job-Certificate\" Schema")
    (_, job_certificate_schema) = await get_schema(pool_handle, acme_did, job_certificate_schema_id)

    logger.info("\"Acme\" -> Create and store in Wallet \"Acme Job-Certificate\" Credential Definition")
    (acme_job_certificate_cred_def_id, acme_job_certificate_cred_def_json) = \
        await anoncreds.issuer_create_and_store_credential_def(acme_wallet[0], acme_did, job_certificate_schema,
                                                               'TAG1', 'CL', '{"support_revocation": false}')

    logger.info("\"Acme\" -> Send \"Acme Job-Certificate\" Credential Definition to Ledger")
    await send_cred_def(pool_handle, acme_wallet[0], acme_did, acme_job_certificate_cred_def_json)

    logger.info("==============================")
    logger.info("=== Getting Transcript with Faber ==")
    logger.info("==============================")
    logger.info("== Getting Transcript with Faber - Onboarding ==")
    logger.info("------------------------------")

    ( alice_faber_did, _ ) = await did.create_and_store_my_did(alice_wallet[0], "{}") # did for get_cred_def_request

    logger.info("==============================")
    logger.info("== Getting Transcript with Faber - Getting Transcript Credential ==")
    logger.info("------------------------------")

    logger.info("\"Faber\" -> Create \"Transcript\" Credential Offer for Alice")
    transcript_cred_offer_json = \
        await anoncreds.issuer_create_credential_offer(faber_wallet[0], faber_transcript_cred_def_id)

    logger.info("\"Faber\" -> Send \"Transcript\" Credential Offer to Alice")

    transcript_cred_offer = json.loads(transcript_cred_offer_json)

    logger.info("\"Alice\" -> Create and store \"Alice\" Master Secret in Wallet")
    alice_master_secret_id = await anoncreds.prover_create_master_secret(alice_wallet[0], None)

    logger.info("\"Alice\" -> Get \"Faber Transcript\" Credential Definition from Ledger")
    #----------------------------------------------------------------------------------------------------------------------------------------------------
    # prover attempt to get cred_def from ledger
    #----------------------------------------------------------------------------------------------------------------------------------------------------
    get_cred_def_request = await ledger.build_get_cred_def_request(alice_faber_did , transcript_cred_offer['cred_def_id'])
    logger.info("cred request" + json.dumps(get_cred_def_request) )
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    #logger.info("cred request response" + json.dumps(get_cred_def_response) )
    (faber_transcript_cred_def_id, faber_transcript_cred_def) = \
        await ledger.parse_get_cred_def_response(get_cred_def_response)
    #----------------------------------------------------------------------------------------------------------------------------------------------------
    #----------------------------------------------------------------------------------------------------------------------------------------------------

    logger.info("\"Alice\" -> Create \"Transcript\" Credential Request for Faber")
    (transcript_cred_request_json, transcript_cred_request_metadata_json) = \
        await anoncreds.prover_create_credential_req(alice_wallet[0], alice_faber_did,
                                                     transcript_cred_offer_json,
                                                     faber_transcript_cred_def, alice_master_secret_id)

    logger.info("\"Alice\" -> Send   \"Transcript\" Credential Request to Faber")

    logger.info("\"Faber\" -> Create \"Transcript\" Credential for Alice")
    transcript_cred_values = json.dumps({
        "first_name": {"raw": "Alice", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
        "degree": {"raw": "Bachelor of Science, Marketing", "encoded": "12434523576212321"},
        "status": {"raw": "graduated", "encoded": "2213454313412354"},
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "year": {"raw": "2015", "encoded": "2015"},
        "average": {"raw": "5", "encoded": "5"}
    })

    transcript_cred_json, _, _ = \
        await anoncreds.issuer_create_credential(faber_wallet[0], transcript_cred_offer_json,
                                                 transcript_cred_request_json,
                                                 transcript_cred_values, None, None)

    logger.info("\"Faber\" -> Send \"Transcript\" Credential to Alice")

    logger.info("\"Alice\" -> Store \"Transcript\" Credential from Faber")
    await anoncreds.prover_store_credential(alice_wallet[0], None, transcript_cred_request_metadata_json,
                                            transcript_cred_json, faber_transcript_cred_def, None)

    logger.info("==============================")
    logger.info("=== Apply for the job with Acme ==")
    logger.info("==============================")
    logger.info("== Apply for the job with Acme - Onboarding ==")
    logger.info("------------------------------")

    ( alice_acme_did, _ ) = await did.create_and_store_my_did(alice_wallet[0], "{}") # did for cred

    logger.info("==============================")
    logger.info("== Apply for the job with Acme - Transcript proving ==")
    logger.info("------------------------------")

    logger.info("\"Acme\" -> Create \"Job-Application\" Proof Request")
    job_application_proof_request_json = json.dumps({
        'nonce': '1432422343242122312411212',
        'name': 'Job-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'degree',
                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
            },
            'attr4_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
            },
            'attr5_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
            },
            'attr6_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'average',
                'p_type': '>=',
                'p_value': 4,
                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
            }
        }
    })

    logger.info("\"Acme\" -> Send \"Job-Application\" Proof Request to Alice")

    logger.info("\"Alice\" -> Get credentials for \"Job-Application\" Proof Request")

    search_for_job_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(alice_wallet[0],
                                                                job_application_proof_request_json, None)

    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)

    creds_for_job_application_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                       cred_for_attr2['referent']: cred_for_attr2,
                                       cred_for_attr3['referent']: cred_for_attr3,
                                       cred_for_attr4['referent']: cred_for_attr4,
                                       cred_for_attr5['referent']: cred_for_attr5,
                                       cred_for_predicate1['referent']: cred_for_predicate1}

    schemas_json, cred_defs_json, revoc_states_json = \
        await prover_get_entities_from_ledger(pool_handle, alice_faber_did, creds_for_job_application_proof, 'Alice')

    logger.info("\"Alice\" -> Create \"Job-Application\" Proof")
    job_application_requested_creds_json = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Alice',
            'attr2_referent': 'Garcia',
            'attr6_referent': '123-45-6789'
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    job_application_proof_json = \
        await anoncreds.prover_create_proof(alice_wallet[0], job_application_proof_request_json,
                                            job_application_requested_creds_json, alice_master_secret_id,
                                            schemas_json, cred_defs_json, revoc_states_json)

    logger.info("\"Alice\" -> Send \"Job-Application\" Proof to Acme")

    decrypted_job_application_proof = json.loads(job_application_proof_json)

    schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json = \
        await verifier_get_entities_from_ledger(pool_handle, acme_did,
                                                decrypted_job_application_proof['identifiers'], 'Acme')

    logger.info("\"Acme\" -> Verify \"Job-Application\" Proof from Alice")
    assert 'Bachelor of Science, Marketing' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'graduated' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr5_referent']['raw']

    assert 'Alice' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Garcia' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr6_referent']

    assert await anoncreds.verifier_verify_proof(job_application_proof_request_json,
                                                 job_application_proof_json,
                                                 schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json)

    logger.info("==============================")
    logger.info("== Apply for the job with Acme - Getting Job-Certificate Credential ==")
    logger.info("------------------------------")

    logger.info("\"Acme\" -> Create \"Job-Certificate\" Credential Offer for Alice")
    job_certificate_cred_offer_json = \
        await anoncreds.issuer_create_credential_offer(acme_wallet[0], acme_job_certificate_cred_def_id)

    logger.info("\"Acme\" -> Send \"Job-Certificate\" Credential Offer to Alice")

    authdecrypted_job_certificate_cred_offer = json.loads(job_certificate_cred_offer_json)
    logger.info("\"Alice\" -> Get \"Acme Job-Certificate\" Credential Definition from Ledger")
    (_, acme_job_certificate_cred_def) = \
        await get_cred_def(pool_handle, alice_acme_did, authdecrypted_job_certificate_cred_offer['cred_def_id'])

    logger.info("\"Alice\" -> Create and store in Wallet \"Job-Certificate\" Credential Request for Acme")
    (job_certificate_cred_request_json, job_certificate_cred_request_metadata_json) = \
        await anoncreds.prover_create_credential_req(alice_wallet[0], alice_acme_did,
                                                     job_certificate_cred_offer_json,
                                                     acme_job_certificate_cred_def, alice_master_secret_id)

    logger.info("\"Alice\" -> Send \"Job-Certificate\" Credential Request to Acme")

    logger.info("\"Acme\" -> Create \"Job-Certificate\" Credential for Alice")
    alice_job_certificate_cred_values_json = json.dumps({
        "first_name": {"raw": "Alice", "encoded": "245712572474217942457235975012103335"},
        "last_name": {"raw": "Garcia", "encoded": "312643218496194691632153761283356127"},
        "employee_status": {"raw": "Permanent", "encoded": "2143135425425143112321314321"},
        "salary": {"raw": "2400", "encoded": "2400"},
        "experience": {"raw": "10", "encoded": "10"}
    })

    job_certificate_cred_json, _, _ = \
        await anoncreds.issuer_create_credential(acme_wallet[0], job_certificate_cred_offer_json,
                                                 job_certificate_cred_request_json,
                                                 alice_job_certificate_cred_values_json, None, None)

    logger.info("\"Acme\" -> Send \"Job-Certificate\" Credential to Alice")

    logger.info("\"Alice\" -> Store \"Job-Certificate\" Credential")
    await anoncreds.prover_store_credential(alice_wallet[0], None, job_certificate_cred_request_metadata_json,
                                            job_certificate_cred_json,
                                            acme_job_certificate_cred_def_json, None)

    logger.info("==============================")
    logger.info("=== Apply for the loan with Thrift ==")
    logger.info("==============================")
    logger.info("== Apply for the loan with Thrift - Onboarding ==")
    logger.info("------------------------------")

    ( alice_thrift_did, _ ) = await did.create_and_store_my_did(alice_wallet[0], "{}")

    logger.info("==============================")
    logger.info("== Apply for the loan with Thrift - Job-Certificate proving  ==")
    logger.info("------------------------------")

    logger.info("\"Thrift\" -> Create \"Loan-Application-Basic\" Proof Request")
    apply_loan_proof_request_json = json.dumps({
        'nonce': '123432421212',
        'name': 'Loan-Application-Basic',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'employee_status',
                'restrictions': [{'cred_def_id': acme_job_certificate_cred_def_id}]
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'salary',
                'p_type': '>=',
                'p_value': 2000,
                'restrictions': [{'cred_def_id': acme_job_certificate_cred_def_id}]
            },
            'predicate2_referent': {
                'name': 'experience',
                'p_type': '>=',
                'p_value': 1,
                'restrictions': [{'cred_def_id': acme_job_certificate_cred_def_id}]
            }
        }
    })

    logger.info("\"Thrift\" -> Send \"Loan-Application-Basic\" Proof Request to Alice")

    logger.info("\"Alice\" -> Get credentials for \"Loan-Application-Basic\" Proof Request")

    search_for_apply_loan_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(alice_wallet[0],
                                                                apply_loan_proof_request_json, None)

    cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'attr1_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate1_referent')
    cred_for_predicate2 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate2_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_proof_request)

    creds_for_apply_loan_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                  cred_for_predicate1['referent']: cred_for_predicate1,
                                  cred_for_predicate2['referent']: cred_for_predicate2}

    schemas_json, cred_defs_json, revoc_states_json = \
        await prover_get_entities_from_ledger(pool_handle, alice_thrift_did, creds_for_apply_loan_proof, 'Alice')

    logger.info("\"Alice\" -> Create \"Loan-Application-Basic\" Proof")
    apply_loan_requested_creds_json = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True}
        },
        'requested_predicates': {
            'predicate1_referent': {'cred_id': cred_for_predicate1['referent']},
            'predicate2_referent': {'cred_id': cred_for_predicate2['referent']}
        }
    })
    alice_apply_loan_proof_json = \
        await anoncreds.prover_create_proof(alice_wallet[0], apply_loan_proof_request_json,
                                            apply_loan_requested_creds_json, alice_master_secret_id, schemas_json,
                                            cred_defs_json, revoc_states_json)

    logger.info("\"Alice\" -> Send \"Loan-Application-Basic\" Proof to Thrift")

    authdecrypted_alice_apply_loan_proof = json.loads(alice_apply_loan_proof_json)
    logger.info("\"Thrift\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                " required for Proof verifying")

    schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
        await verifier_get_entities_from_ledger(pool_handle, thrift_did,
                                                authdecrypted_alice_apply_loan_proof['identifiers'], 'Thrift')

    logger.info("\"Thrift\" -> Verify \"Loan-Application-Basic\" Proof from Alice")
    assert 'Permanent' == \
           authdecrypted_alice_apply_loan_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']

    assert await anoncreds.verifier_verify_proof(apply_loan_proof_request_json,
                                                 alice_apply_loan_proof_json,
                                                 schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)

    logger.info("==============================")

    logger.info("==============================")
    logger.info("== Apply for the loan with Thrift - Transcript and Job-Certificate proving  ==")
    logger.info("------------------------------")

    logger.info("\"Thrift\" -> Create \"Loan-Application-KYC\" Proof Request")
    apply_loan_kyc_proof_request_json = json.dumps({
        'nonce': '123432421212',
        'name': 'Loan-Application-KYC',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {'name': 'first_name'},
            'attr2_referent': {'name': 'last_name'},
            'attr3_referent': {'name': 'ssn'}
        },
        'requested_predicates': {}
    })

    logger.info("\"Thrift\" -> Send \"Loan-Application-KYC\" Proof Request to Alice")

    logger.info("\"Alice\" -> Get credentials for \"Loan-Application-KYC\" Proof Request")

    search_for_apply_loan_kyc_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(alice_wallet[0],
                                                                apply_loan_kyc_proof_request_json, None)

    cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr3_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_kyc_proof_request)

    creds_for_apply_loan_kyc_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                      cred_for_attr2['referent']: cred_for_attr2,
                                      cred_for_attr3['referent']: cred_for_attr3}

    schemas_json, cred_defs_json, revoc_states_json = \
        await prover_get_entities_from_ledger(pool_handle, alice_thrift_did, creds_for_apply_loan_kyc_proof, 'Alice')

    logger.info("\"Alice\" -> Create \"Loan-Application-KYC\" Proof")

    apply_loan_kyc_requested_creds_json = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
            'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True}
        },
        'requested_predicates': {}
    })

    alice_apply_loan_kyc_proof_json = \
        await anoncreds.prover_create_proof(alice_wallet[0], apply_loan_kyc_proof_request_json,
                                            apply_loan_kyc_requested_creds_json, alice_master_secret_id,
                                            schemas_json, cred_defs_json, revoc_states_json)

    logger.info("\"Alice\" -> Send \"Loan-Application-KYC\" Proof to Thrift")

    authdecrypted_alice_apply_loan_kyc_proof = json.loads(alice_apply_loan_kyc_proof_json)
    logger.info("\"Thrift\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                " required for Proof verifying")

    schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
        await verifier_get_entities_from_ledger(pool_handle, thrift_did,
                                                authdecrypted_alice_apply_loan_kyc_proof['identifiers'], 'Thrift')

    logger.info("\"Thrift\" -> Verify \"Loan-Application-KYC\" Proof from Alice")
    assert 'Alice' == \
           authdecrypted_alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert 'Garcia' == \
           authdecrypted_alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert '123-45-6789' == \
           authdecrypted_alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']

    assert await anoncreds.verifier_verify_proof(apply_loan_kyc_proof_request_json,
                                                 alice_apply_loan_kyc_proof_json,
                                                 schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)

    logger.info("==============================")
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

    logger.info("Close pool")
    #logger.info("Close and Delete pool")
    await pool.close_pool_ledger(pool_handle)
    #await pool.delete_pool_ledger_config(pool_name)

    logger.info("Getting started -> done")

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


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)

async def get_schema_with_fees(pool_handle, wallet_handle, inputs, outputs, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_request = await payment.add_request_fees(wallet_handle, _did, get_schema_request,inputs,outputs, None )
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)

async def get_cred_def(pool_handle, _did, schema_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, schema_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
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

        if 'rev_reg_seq_no' in item:
            pass  # TODO Create Revocation States

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
