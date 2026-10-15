// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {QstampAnchor, IPostQuantumEvidenceAnchor} from "../src/QstampAnchor.sol";

contract QstampAnchorTest is Test {
    QstampAnchor internal anchor;

    event Anchored(
        address indexed signer,
        bytes32 indexed kind,
        bytes32 commitment,
        uint64 batchSize,
        uint256 timestamp
    );

    function setUp() public {
        anchor = new QstampAnchor();
    }

    function commitmentOf(bytes32 fingerprint, address signer, bytes32 kind)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(fingerprint, signer, kind));
    }

    function testAnchorStoresTimestampAndEmits() public {
        bytes32 c = commitmentOf(keccak256("r"), address(this), bytes32("qstamp"));
        vm.warp(1_700_000_000);
        vm.expectEmit(true, true, true, true);
        emit Anchored(address(this), bytes32("qstamp"), c, 1, 1_700_000_000);
        anchor.anchor(c, bytes32("qstamp"), 1);
        assertEq(anchor.anchored(c), 1_700_000_000);
    }

    function testUnknownCommitmentReturnsZero() public view {
        assertEq(anchor.anchored(keccak256("never")), 0);
    }

    function testZeroCommitmentReverts() public {
        vm.expectRevert(QstampAnchor.ZeroCommitment.selector);
        anchor.anchor(bytes32(0), bytes32("qstamp"), 1);
    }

    function testZeroBatchSizeReverts() public {
        bytes32 c = commitmentOf(keccak256("r"), address(this), bytes32("qstamp"));
        vm.expectRevert(QstampAnchor.ZeroBatchSize.selector);
        anchor.anchor(c, bytes32("qstamp"), 0);
    }

    function testDoubleAnchorReverts() public {
        bytes32 c = commitmentOf(keccak256("r"), address(this), bytes32("qstamp"));
        anchor.anchor(c, bytes32("qstamp"), 1);
        vm.expectRevert(abi.encodeWithSelector(QstampAnchor.AlreadyAnchored.selector, c));
        anchor.anchor(c, bytes32("qstamp"), 1);
    }

    function testFirstTimestampIsKept() public {
        bytes32 c = commitmentOf(keccak256("r"), address(this), bytes32("qstamp"));
        vm.warp(1000);
        anchor.anchor(c, bytes32("qstamp"), 1);
        vm.warp(2000);
        vm.expectRevert(abi.encodeWithSelector(QstampAnchor.AlreadyAnchored.selector, c));
        anchor.anchor(c, bytes32("qstamp"), 1);
        assertEq(anchor.anchored(c), 1000);
    }

    function testSameFingerprintDistinctSignersDoNotCollide() public pure {
        bytes32 fp = keccak256("record");
        bytes32 a = commitmentOf(fp, address(0xA11CE), bytes32("qstamp"));
        bytes32 b = commitmentOf(fp, address(0xB0B), bytes32("qstamp"));
        assertTrue(a != b);
    }

    function testDistinctSignersAnchorIndependently() public {
        bytes32 fp = keccak256("record");
        bytes32 ca = commitmentOf(fp, address(0xA11CE), bytes32("qstamp"));
        bytes32 cb = commitmentOf(fp, address(0xB0B), bytes32("qstamp"));
        vm.prank(address(0xA11CE));
        anchor.anchor(ca, bytes32("qstamp"), 1);
        vm.prank(address(0xB0B));
        anchor.anchor(cb, bytes32("qstamp"), 1);
        assertGt(anchor.anchored(ca), 0);
        assertGt(anchor.anchored(cb), 0);
    }

    function testFuzzAnchorRoundTrips(bytes32 c, bytes32 kind, uint64 batchSize, uint256 ts)
        public
    {
        vm.assume(c != bytes32(0));
        vm.assume(batchSize != 0);
        vm.assume(ts != 0 && ts < 2 ** 64);
        vm.warp(ts);
        anchor.anchor(c, kind, batchSize);
        assertEq(anchor.anchored(c), ts);
    }
}
