// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.26;
import {Test} from "forge-std/Test.sol";
contract Parity is Test {
    function testParity() public pure {
        bytes32 fp = 0x31f96f64ce5d5e47aee5172318531c8348ad57d2943a0c7fab298dd59b7852d4;
        address signer = 0x00000000000000000000000000000000000000AA;
        bytes32 kind = bytes32(0x0000000000000000000000000000000000000000000000000000717374616d70);
        bytes32 c = keccak256(abi.encode(fp, signer, kind));
        assertEq(c, 0x566469d333fd838a77d137d344b059ac0bd6cf471573ae21d1cc7bc0eec235d2);
    }
}
