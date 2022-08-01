// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

// never forget the OG simple sig wallet: https://github.com/christianlundkvist/simple-multisig/blob/master/contracts/SimpleMultiSig.sol

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./MultiSigFactory.sol";

contract MultiSigWallet {
    using ECDSA for bytes32;

    MultiSigFactory private multiSigFactory; // factory

    event Deposit(address indexed sender, uint256 amount, uint256 balance);
    event ExecuteTransaction(
        address indexed owner,
        address payable to,
        uint256 value,
        bytes data,
        uint256 nonce,
        bytes32 hash,
        bytes result
    );
    event Owner(address indexed owner, bool added);

    mapping(address => bool) public isOwner;

    address[] public owners;

    uint256 public signaturesRequired;
    uint256 public nonce;
    uint256 public chainId;

    modifier onlyOwner() {
        require(isOwner[msg.sender], "Not owner");
        _;
    }

    modifier onlySelf() {
        require(msg.sender == address(this), "Not Self");
        _;
    }

    modifier requireNonZeroSignatures(uint256 _signaturesRequired) {
        require(_signaturesRequired > 0, "Must be non-zero sigs required");
        _;
    }

    constructor(
        uint256 _chainId,
        address[] memory _owners,
        uint256 _signaturesRequired,
        address _factory
    ) payable requireNonZeroSignatures(_signaturesRequired) {        
        uint256 ownersCount = _owners.length;
        require(_signaturesRequired <= ownersCount, "Must be less than or equal to owners count");

        multiSigFactory = MultiSigFactory(_factory);
        signaturesRequired = _signaturesRequired;
        chainId = _chainId;
        for (uint256 i = 0; i < ownersCount; i++) {
            address owner = _owners[i];

            require(owner != address(0), "constructor: zero address");
            require(!isOwner[owner], "constructor: owner not unique");

            isOwner[owner] = true;
            owners.push(owner);

            emit Owner(owner, true);
        }
    }

    function addSigner(address newSigner, uint256 newSignaturesRequired)
        public
        onlySelf
        requireNonZeroSignatures(newSignaturesRequired)
    {
        require(newSigner != address(0), "addSigner: zero address");
        require(!isOwner[newSigner], "addSigner: owner not unique");

        isOwner[newSigner] = true;
        owners.push(newSigner);
        signaturesRequired = newSignaturesRequired;

        emit Owner(newSigner, true);
        multiSigFactory.emitOwners(
            address(this),
            owners,
            newSignaturesRequired
        );
    }

    function removeSigner(address oldSigner, uint256 newSignaturesRequired)
        public
        onlySelf
        requireNonZeroSignatures(newSignaturesRequired)
    {
        _removeOwner(oldSigner);
        signaturesRequired = newSignaturesRequired;

        emit Owner(oldSigner, isOwner[oldSigner]);
        multiSigFactory.emitOwners(
            address(this),
            owners,
            newSignaturesRequired
        );
    }

    function _removeOwner(address _oldSigner) private onlySelf {
        delete isOwner[_oldSigner];
        uint256 ownersLength = owners.length;
        for (uint256 i = 0; i < ownersLength; i++) {
            if (owners[i] == _oldSigner) {
                owners[i] = owners[ownersLength - 1];
                owners.pop();
                return;
            }
        }
    }

    function updateSignaturesRequired(uint256 newSignaturesRequired)
        public
        onlySelf
        requireNonZeroSignatures(newSignaturesRequired)
    {
        signaturesRequired = newSignaturesRequired;
    }

    function executeTransaction(
        address payable to,
        uint256 value,
        bytes memory data,
        bytes[] memory signatures
    ) public onlyOwner returns (bytes memory) {
        bytes32 _hash = getTransactionHash(nonce, to, value, data);

        nonce++;

        uint256 validSignatures;
        address duplicateGuard;

        uint256 signaturesCount = signatures.length;
        for (uint256 i = 0; i < signaturesCount; i++) {
            address recovered = recover(_hash, signatures[i]);
            require(
                recovered > duplicateGuard,
                "executeTransaction: duplicate or unordered signatures"
            );
            duplicateGuard = recovered;

            if (isOwner[recovered]) {
                validSignatures++;
            }
        }

        require(
            validSignatures >= signaturesRequired,
            "executeTransaction: not enough valid signatures"
        );

        (bool success, bytes memory result) = to.call{value: value}(data);
        require(success, "executeTransaction: tx failed");

        emit ExecuteTransaction(
            msg.sender,
            to,
            value,
            data,
            nonce - 1,
            _hash,
            result
        );
        return result;
    }

    function getTransactionHash(
        uint256 _nonce,
        address to,
        uint256 value,
        bytes memory data
    ) public view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    address(this),
                    chainId,
                    _nonce,
                    to,
                    value,
                    data
                )
            );
    }

    function recover(bytes32 _hash, bytes memory _signature)
        public
        pure
        returns (address)
    {
        return _hash.toEthSignedMessageHash().recover(_signature);
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value, address(this).balance);
    }

    fallback() external payable {
        emit Deposit(msg.sender, msg.value, address(this).balance);
    }
}
