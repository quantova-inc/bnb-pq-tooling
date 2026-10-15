// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.26;

interface IPostQuantumEvidenceAnchor {
    event Anchored(
        address indexed signer,
        bytes32 indexed kind,
        bytes32 commitment,
        uint64 batchSize,
        uint256 timestamp
    );

    function anchor(bytes32 commitment, bytes32 kind, uint64 batchSize) external;

    function anchored(bytes32 commitment) external view returns (uint256 timestamp);
}

contract QstampAnchor is IPostQuantumEvidenceAnchor {
    mapping(bytes32 => uint256) private _anchoredAt;

    error ZeroCommitment();
    error ZeroBatchSize();
    error AlreadyAnchored(bytes32 commitment);

    function anchor(bytes32 commitment, bytes32 kind, uint64 batchSize) external {
        if (commitment == bytes32(0)) {
            revert ZeroCommitment();
        }
        if (batchSize == 0) {
            revert ZeroBatchSize();
        }
        if (_anchoredAt[commitment] != 0) {
            revert AlreadyAnchored(commitment);
        }
        _anchoredAt[commitment] = block.timestamp;
        emit Anchored(msg.sender, kind, commitment, batchSize, block.timestamp);
    }

    function anchored(bytes32 commitment) external view returns (uint256 timestamp) {
        return _anchoredAt[commitment];
    }
}
