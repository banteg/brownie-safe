import json
import tempfile
from pathlib import Path

import pytest
from ape.utils import ZERO_ADDRESS

from ape_safe.accounts import SafeAccount


@pytest.fixture(scope="session")
def deployer(accounts):
    return accounts[-1]


@pytest.fixture(scope="session", params=["1.3.0"])  # TODO: Test more versions later?
def VERSION(request):
    return request.param


@pytest.fixture(scope="session")
def SafeSingleton(project, VERSION):
    return project.dependencies["safe-contracts"][VERSION]["GnosisSafe"]


@pytest.fixture
def singleton(deployer, SafeSingleton):
    return deployer.deploy(SafeSingleton)


@pytest.fixture(scope="session")
def SafeProxy(project, SafeSingleton, VERSION):
    Proxy = project.dependencies["safe-contracts"][VERSION]["GnosisSafeProxy"]
    IProxy = project.dependencies["safe-contracts"][VERSION]["IProxy"]
    # NOTE: Proxy only has a constructor, so we add the rest of it's ABI here for simplified use
    Proxy.contract_type.abi += [IProxy.contract_type.abi[0], *SafeSingleton.contract_type.abi]
    return Proxy


@pytest.fixture(params=["1/1", "1/2", "2/2", "2/3"])
def MULTISIG_TYPE(request):
    # Param is `M/N`, but encoded as a string for repr in pytest
    return request.param.split("/")


@pytest.fixture
def THRESHOLD(MULTISIG_TYPE):
    M, _ = MULTISIG_TYPE
    return int(M)


@pytest.fixture
def OWNERS(accounts, MULTISIG_TYPE):
    _, N = MULTISIG_TYPE
    return accounts[: int(N)]


@pytest.fixture
def safe_contract(singleton, SafeProxy, OWNERS, THRESHOLD):
    deployer = OWNERS[0]
    safe = deployer.deploy(SafeProxy, singleton)
    safe.setup(
        OWNERS,
        THRESHOLD,
        # no modules
        ZERO_ADDRESS,
        b"",
        # no fallback
        ZERO_ADDRESS,
        # no payment
        ZERO_ADDRESS,
        0,
        ZERO_ADDRESS,
        sender=deployer,
    )
    return safe


@pytest.fixture
def safe_data_file(chain, safe_contract):
    with tempfile.NamedTemporaryFile() as fp:
        file = Path(str(fp.name))
        file.write_text(
            json.dumps(
                {
                    "address": safe_contract.address,
                    "deployed_chain_ids": [chain.provider.chain_id],
                }
            )
        )
        yield file


@pytest.fixture
def safe(safe_data_file):
    # TODO: Mock `SafeAccount.client` or use local client
    return SafeAccount(account_file_path=safe_data_file)
