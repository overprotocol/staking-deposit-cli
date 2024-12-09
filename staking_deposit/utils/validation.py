import click
import json
import re
from typing import Any, Dict, Sequence

from eth_typing import (
    BLSPubkey,
    BLSSignature,
    HexAddress,
)
from eth_utils import is_hex_address, is_checksum_address, to_normalized_address
from py_ecc.bls import G2ProofOfPossession as bls

from staking_deposit.exceptions import ValidationError
from staking_deposit.utils.intl import load_text
from staking_deposit.utils.ssz import (
    DepositData,
    DepositMessage,
    compute_deposit_domain,
    compute_signing_root,
)
from staking_deposit.credentials import (
    Credential,
)
from staking_deposit.utils.constants import (
    MAX_DEPOSIT_AMOUNT,
    MIN_DEPOSIT_AMOUNT,
    ETH2GWEI,
    WITHDRAWAL_PREFIX,
)
from staking_deposit.utils.crypto import SHA256
from staking_deposit.settings import BaseChainSetting


#
# Deposit
#

def verify_deposit_data_json(filefolder: str, credentials: Sequence[Credential]) -> bool:
    """
    Validate every deposit found in the deposit-data JSON file folder.
    """
    with open(filefolder, 'r') as f:
        deposit_json = json.load(f)
        with click.progressbar(deposit_json, label=load_text(['msg_deposit_verification']),
                               show_percent=False, show_pos=True) as deposits:
            return all([validate_deposit(deposit, credential) for deposit, credential in zip(deposits, credentials)])
    return False


def validate_deposit(deposit_data_dict: Dict[str, Any], credential: Credential) -> bool:
    '''
    Checks whether a deposit is valid based on the staking deposit rules.
    https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#deposits
    '''
    pubkey = BLSPubkey(bytes.fromhex(deposit_data_dict['pubkey']))
    withdrawal_credentials = bytes.fromhex(deposit_data_dict['withdrawal_credentials'])
    amount = deposit_data_dict['amount']
    signature = BLSSignature(bytes.fromhex(deposit_data_dict['signature']))
    deposit_message_root = bytes.fromhex(deposit_data_dict['deposit_data_root'])
    fork_version = bytes.fromhex(deposit_data_dict['fork_version'])

    # Verify pubkey
    if len(pubkey) != 48:
        return False
    if pubkey != credential.signing_pk:
        return False

    # Verify withdrawal credential
    if len(withdrawal_credentials) != 32:
        return False
    if withdrawal_credentials[:1] == WITHDRAWAL_PREFIX == credential.withdrawal_prefix:
        if withdrawal_credentials[1:12] != b'\x00' * 11:
            return False
        if credential.eth1_withdrawal_address is None:
            return False
        if withdrawal_credentials[12:] != credential.eth1_withdrawal_address:
            return False
    else:
        return False

    # Verify deposit amount
    if not MIN_DEPOSIT_AMOUNT <= amount <= MAX_DEPOSIT_AMOUNT:
        return False

    # Verify deposit signature && pubkey
    deposit_message = DepositMessage(pubkey=pubkey, withdrawal_credentials=withdrawal_credentials, amount=amount)
    domain = compute_deposit_domain(fork_version)
    signing_root = compute_signing_root(deposit_message, domain)
    if not bls.Verify(pubkey, signing_root, signature):
        return False

    # Verify Deposit Root
    signed_deposit = DepositData(
        pubkey=pubkey,
        withdrawal_credentials=withdrawal_credentials,
        amount=amount,
        signature=signature,
    )
    return signed_deposit.hash_tree_root == deposit_message_root


def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        raise ValidationError(load_text(['msg_password_length']))
    return password


def validate_int_range(num: Any, low: int, high: int) -> int:
    '''
    Verifies that `num` is an `int` andlow <= num < high
    '''
    try:
        num_int = int(num)  # Try cast to int
        assert num_int == float(num)  # Check num is not float
        assert low <= num_int < high  # Check num in range
        return num_int
    except (ValueError, AssertionError):
        raise ValidationError(load_text(['err_not_positive_integer']))

def validate_deposit_amount(amount: Any) -> int:
    '''
    Verifies that `amount` is an `int` and MIN_DEPOSIT_AMOUNT <= num < MAX_DEPOSIT_AMOUNT
    '''
    try:
        amount_int = int(amount)  # Try cast to int
        assert amount_int == float(amount)  # Check amount is not float
        amount_int_in_gwei = amount_int * ETH2GWEI
        assert MIN_DEPOSIT_AMOUNT <= amount_int_in_gwei <= MAX_DEPOSIT_AMOUNT  # Check amount in range
        return amount_int
    except (ValueError, AssertionError):
        raise ValidationError(load_text(['err_not_valid_deposit_amount']))


def validate_eth1_withdrawal_address(cts: click.Context, param: Any, address: str) -> HexAddress:
    if address is None:
        return None
    if not is_hex_address(address):
        raise ValidationError(load_text(['err_invalid_ECDSA_hex_addr']))
    if not is_checksum_address(address):
        raise ValidationError(load_text(['err_invalid_ECDSA_hex_addr_checksum']))

    normalized_address = to_normalized_address(address)
    return normalized_address


def is_eth1_address_withdrawal_credentials(withdrawal_credentials: bytes) -> bool:
    return (
        len(withdrawal_credentials) == 32
        and withdrawal_credentials[:1] == WITHDRAWAL_PREFIX
        and withdrawal_credentials[1:12] == b'\x00' * 11
    )


def normalize_input_list(input: str) -> Sequence[str]:
    try:
        input = input.strip('[({})]')
        input = re.sub(' +', ' ', input)
        result = re.split(r'; |, | |,|;', input)
    except Exception:
        raise ValidationError(load_text(['err_incorrect_list']) + '\n')
    return result
