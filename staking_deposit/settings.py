from typing import Dict, NamedTuple
from eth_utils import decode_hex

DEPOSIT_CLI_VERSION = '2.7.1'


class BaseChainSetting(NamedTuple):
    NETWORK_NAME: str
    GENESIS_FORK_VERSION: bytes
    GENESIS_VALIDATORS_ROOT: bytes


MAINNET = 'mainnet'
OVER = 'over'
OVER_DOLPHIN = 'over_dolphin'

# Mainnet setting (Ethereum Mainnet)
MainnetSetting = BaseChainSetting(
    NETWORK_NAME=MAINNET, GENESIS_FORK_VERSION=bytes.fromhex('00000000'),
    GENESIS_VALIDATORS_ROOT=bytes.fromhex('4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95'))
# Over Setting
OverSetting = BaseChainSetting(
    NETWORK_NAME=OVER, GENESIS_FORK_VERSION=bytes.fromhex('00000018'),
    GENESIS_VALIDATORS_ROOT=bytes.fromhex('e24c5db2b830319137301a75decfdd5e793f7f7acd6817727996f824856cc8dd'))
# Over Dolphin Setting
OverDolphinSetting = BaseChainSetting(
    NETWORK_NAME=OVER_DOLPHIN, GENESIS_FORK_VERSION=bytes.fromhex('00000028'),
    GENESIS_VALIDATORS_ROOT=bytes.fromhex('9827ccaceeee4a16f78091d3ce4dce4e45d7c6d2793e571e8b59dcaff3d1804f'))



ALL_CHAINS: Dict[str, BaseChainSetting] = {
    MAINNET: MainnetSetting,
    OVER: OverSetting,
    OVER_DOLPHIN: OverDolphinSetting,
}


def get_chain_setting(chain_name: str = OVER) -> BaseChainSetting:
    return ALL_CHAINS[chain_name]


def get_devnet_chain_setting(network_name: str,
                             genesis_fork_version: str,
                             genesis_validator_root: str) -> BaseChainSetting:
    return BaseChainSetting(
        NETWORK_NAME=network_name,
        GENESIS_FORK_VERSION=decode_hex(genesis_fork_version),
        GENESIS_VALIDATORS_ROOT=decode_hex(genesis_validator_root),
    )
