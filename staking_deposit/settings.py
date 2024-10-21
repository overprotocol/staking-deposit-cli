from typing import Dict, NamedTuple
from eth_utils import decode_hex

DEPOSIT_CLI_VERSION = '2.7.0'


class BaseChainSetting(NamedTuple):
    NETWORK_NAME: str
    GENESIS_FORK_VERSION: bytes
    GENESIS_VALIDATORS_ROOT: bytes


MAINNET = 'mainnet'
OVER = 'over'
OVER_DOLPHIN = 'over_dolphin'
OVER_ALPACA_1 = 'over_alpaca_1'

# Mainnet setting (Ethereum Mainnet)
MainnetSetting = BaseChainSetting(
    NETWORK_NAME=MAINNET, GENESIS_FORK_VERSION=bytes.fromhex('00000000'),
    GENESIS_VALIDATORS_ROOT=bytes.fromhex('4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95'))
# Over Setting
OverSetting = BaseChainSetting(
    NETWORK_NAME=OVER, GENESIS_FORK_VERSION=bytes.fromhex('00000018'),
    GENESIS_VALIDATORS_ROOT=bytes.fromhex('632a76efc7571a6b21a29156dec3ede1647cf6832f11b4a14b5a1f00b2a4d67e'))
# Over Dolphin Setting
OverDolphinSetting = BaseChainSetting(
    NETWORK_NAME=OVER_DOLPHIN, GENESIS_FORK_VERSION=bytes.fromhex('00000028'),
    GENESIS_VALIDATORS_ROOT=bytes.fromhex('48353842925cb3ef54869b14c454baf57d106ec9f79bc67d77ba78cc59f70625'))
OverAlpaca1Setting = BaseChainSetting(
    NETWORK_NAME=OVER_ALPACA_1, GENESIS_FORK_VERSION=bytes.fromhex('20000089'),
    GENESIS_VALIDATORS_ROOT=bytes.fromhex('bb2eeb219872516ca0f92f3e7af8a34a7d306438cdedaae99b42a5af9d979156'))



ALL_CHAINS: Dict[str, BaseChainSetting] = {
    MAINNET: MainnetSetting,
    OVER: OverSetting,
    OVER_DOLPHIN: OverDolphinSetting,
    OVER_ALPACA_1: OverAlpaca1Setting,
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
