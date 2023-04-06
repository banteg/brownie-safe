# Working with NPM dependencies is broken: https://github.com/ApeWorX/ape/issues/1327
# And also the settings are weird: https://github.com/ApeWorX/ape/issues/1221
# This is what I did to build the `safe-contracts` dependency
# And then put manifest at `~/.ape/packages/safe-contracts/v1.3.0/safe-contracts.json`

git clone https://github.com/safe-global/safe-contracts
cd safe-contracts
git checkout v1.3.0
rm -rf contracts/test
rm -f contracts/interfaces/ViewStorageAccessible.sol
cat<<EOF
dependencies:
  - name: OpenZeppelin
    github: OpenZeppelin/openzeppelin-contracts
    version: 3.4.0
  - name: mock-contract
    github: gnosis/mock-contract
    branch: solidity_0.7
  - name: safe-singleton-factory
    github: safe-global/safe-singleton-factory
    version: 1.0.11

solidity:
  import_remapping:
    - "@openzeppelin/contracts=OpenZeppelin/3.4.0"
    - "@gnosis.pm/mock-contract/contracts=mock-contract/solidity_0.7"
    - "@gnosis.pm/safe-singletoken-factory/contracts=safe-singleton-factory/1.0.11"
  version: 0.7.6
EOF
ape compile
cd ..
rm -rf safe-contracts
