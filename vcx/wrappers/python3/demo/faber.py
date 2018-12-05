import asyncio
import json
import random
from ctypes import cdll
from time import sleep

import pyqrcode
#import qrcode_terminal
from giphypop import screensaver
from indy import anoncreds, crypto, did, ledger, pool, wallet, payment, blob_storage

from vcx.api.vcx_init import vcx_init_with_config
from vcx.api.connection import Connection
from vcx.api.issuer_credential import IssuerCredential
from vcx.api.proof import Proof
from vcx.api.schema import Schema
from vcx.api.credential_def import CredentialDef
from vcx.state import State, ProofState
from vcx.api.utils import vcx_agent_provision
from vcx.api.wallet import Wallet as vcxWallet

# 'agency_url': URL of the agency
# 'agency_did':  public DID of the agency
# 'agency_verkey': public verkey of the agency
# 'wallet_name': name for newly created encrypted wallet
# 'wallet_key': encryption key for encoding wallet
# 'payment_method': method that will be used for payments
provisionConfig = {
  #'agency_url':'http://localhost:8080',
  'agency_url':'http://18.188.30.211:30800',
  'agency_did':'VsKV7grR1BUE29mG2Fm2kX',
  'agency_verkey':'Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR',
  'wallet_name':'faber_wallet',
  'wallet_key':'123',
  'payment_method': 'null',
  'enterprise_seed':'000000000000000000000000Trustee1',
  'export_path':'faberbackup',
  #'export_path':'/c/Users/burdettadam/Documents/GitHub/indy-sdk/vcx/wrappers/python3/demo/backup',
  'backup_key':'this is the right place'
}


async def main():

    try:
        #await wallet.close_wallet(wallet_handle)
        await wallet.delete_wallet(json.dumps({"id": provisionConfig["wallet_name"]}), json.dumps({"key": provisionConfig["wallet_key"]}))
    except :
        pass

    payment_plugin = cdll.LoadLibrary("libnullpay.so")
    payment_plugin.nullpay_init()

    print("#1 Provision an agent and wallet, get back configuration details")
    config = await vcx_agent_provision(json.dumps(provisionConfig))
    config = json.loads(config)
    # Set some additional configuration options specific to faber
    config['institution_name'] = 'Faber'
    institution_logo_url = screensaver("adventure time")["original"]["url"]
    config['institution_logo_url'] = institution_logo_url
    config['genesis_path'] = 'docker.txn'
    
    print("#2 Initialize libvcx with new configuration")
    await vcx_init_with_config(json.dumps(config))

    print("#3 Create a new schema on the ledger")
    version = format("%d.%d.%d" % (random.randint(1, 101), random.randint(1, 101), random.randint(1, 101)))
    schema = await Schema.create('schema_uuid', 'degree schema', version, ['name', 'date', 'degree'], 0)
    schema_id = await schema.get_schema_id()

    print("#4 Create a new credential definition on the ledger")
    cred_def = await CredentialDef.create('credef_uuid', 'degree', schema_id, 0)
    cred_def_id = await cred_def.get_cred_def_id()
    print("cred_def_id")
    print(cred_def_id)
    print("#5 Create a connection to alice and print out the invite details")
    connection_to_alice = await Connection.create('alice')
    await connection_to_alice.connect(None)
    await connection_to_alice.update_state()
    details = await connection_to_alice.invite_details(False)
    print("**invite details**")
    print(json.dumps(details))
    offer = convertInvite(details)
    offer["s"]["n"] = "Faber"
    offer["t"] = "Faber"
    offer["s"]["l"] = institution_logo_url
    #print(json.dumps(offer))
    pyqrcode.create(json.dumps(offer)).png('qr-code-connection-offer.png', scale=3, module_color=[0, 0, 0, 128], background=[0xff, 0xff, 0xcc])
    print("******************")
    #------------------------------------------------------------------------------------------------------
    # export wallet 
    #await vcxWallet.export(provisionConfig["export_path"],provisionConfig["backup_key"])
    # delete wallet
    #await wallet.delete_wallet(json.dumps({"id": provisionConfig["wallet_name"]}), json.dumps({"key": provisionConfig["wallet_key"]}))
    # import wallet
    '''importConfig= {
        "wallet_name":provisionConfig["wallet_name"],
        #"wallet_key":"random thing",
        "wallet_key":provisionConfig["wallet_key"],
        "exported_wallet_path":provisionConfig["export_path"],
        "backup_key":provisionConfig["backup_key"]
    }'''
    #await vcxWallet.import_wallet(json.dumps(importConfig))
    #------------------------------------------------------------------------------------------------------

    print("#6 Poll agency and wait for alice to accept the invitation (start alice.py now)")
    connection_state = await connection_to_alice.get_state()
    print("\n\nbefore accepted connection_to_alice.serialize()")
    print(await connection_to_alice.serialize())
    while connection_state != State.Accepted:
        sleep(4)
        await connection_to_alice.update_state()
        connection_state = await connection_to_alice.get_state()
    print("\n\nafter accepted connection_to_alice.serialize()")
    print(await connection_to_alice.serialize())
    schema_attrs = {
        'name': 'alice',
        'date': '05-2018',
        'degree': 'maths',
    }

    print("#12 Create an IssuerCredential object using the schema and credential definition")
    credential = await IssuerCredential.create('alice_degree', schema_attrs, cred_def_id, 'cred', '0')

    print("#13 Issue credential offer to alice")
    await credential.send_offer(connection_to_alice)

    await credential.update_state()
    print(await credential.serialize())

    print("#14 Poll agency and wait for alice to send a credential request")
    credential_state = await credential.get_state()
    print("\n\nbefore cred req credential.serialize()")
    print(await credential.serialize())
    while credential_state != State.RequestReceived:
        sleep(2)
        await credential.update_state()
        credential_state = await credential.get_state()
    print("\n\nafter cred req credential.serialize()")
    print(await credential.serialize())


    print("#17 Issue credential to alice")
    await credential.send_credential(connection_to_alice)

    print("#18 Wait for alice to accept credential")
    await credential.update_state()
    credential_state = await credential.get_state()
    print("\n\nBefore accept credential.serialize()")
    print(await credential.serialize())
    while credential_state != State.Accepted:
        sleep(2)
        await credential.update_state()
        credential_state = await credential.get_state()
    print("\n\nAfter accept credential.serialize()")
    print(await credential.serialize())
    #input("Press Enter to continue...")

    proof_attrs = [
        {'name': 'name', 'restrictions': [{'issuer_did': config['institution_did']}]},
        {'name': 'date', 'restrictions': [{'issuer_did': config['institution_did']}]},
        {'name': 'degree', 'restrictions': [{'issuer_did': config['institution_did']}]}
    ]

    print("#19 Create a Proof object")
    proof = await Proof.create('proof_uuid', 'proof_from_alice', proof_attrs)

    print("#20 Request proof of degree from alice")
    await proof.request_proof(connection_to_alice)

    print("#21 Poll agency and wait for alice to provide proof")
    proof_state = await proof.get_state()
    while proof_state != State.Accepted:
        sleep(2)
        await proof.update_state()
        proof_state = await proof.get_state()

    print("#27 Process the proof provided by alice")
    await proof.get_proof(connection_to_alice)

    print("#28 Check if proof is valid")
    if proof.proof_state == ProofState.Verified:
        print("proof is verified!!")
    else:
        print("could not verify proof :(")

def convertInvite(invite):
    return{ "id": invite["connReqId"],
            "s" :{"d" :invite["senderDetail"]["DID"],
                    "dp":{"d":invite["senderDetail"]["agentKeyDlgProof"]["agentDID"],
                          "k":invite["senderDetail"]["agentKeyDlgProof"]["agentDelegatedKey"],
                          "s":invite["senderDetail"]["agentKeyDlgProof"]["signature"]
                        },
                    "l" :invite["senderDetail"]["logoUrl"],
                    "n" :invite["senderDetail"]["name"],
                    "v" :invite["senderDetail"]["verKey"]
                    },
            "sa":{"d":invite["senderAgencyDetail"]["DID"],
                    "e":invite["senderAgencyDetail"]["endpoint"],
                    "v":invite["senderAgencyDetail"]["verKey"]
                },
            "sc":invite["statusCode"],
            "sm":invite["statusMsg"],
            "t" :invite["targetName"]
            }

import pprint
pp = pprint.PrettyPrinter(indent=4)
def deepDump(obj):
    for attr in dir(obj):
        print("obj.%s = %r" % (attr, getattr(obj, attr)))
        pp.pprint(attr)
'''
from collections import Mapping, Set, Sequence 

string_types = (str, unicode) if str is bytes else (str, bytes)
iteritems = lambda mapping: getattr(mapping, 'iteritems', mapping.items)()

def deepDump(obj, path=(), memo=None):
    if memo is None:
        memo = set()
    iterator = None
    if isinstance(obj, Mapping):
        iterator = iteritems
    elif isinstance(obj, (Sequence, Set)) and not isinstance(obj, string_types):
        iterator = enumerate
    if iterator:
        if id(obj) not in memo:
            memo.add(id(obj))
            for path_component, value in iterator(obj):
                for result in objwalk(value, path + (path_component,), memo):
                    yield result
            memo.remove(id(obj))
    else:
        yield path, obj
        print("path.%s = %r" % (path,obj))
'''

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
