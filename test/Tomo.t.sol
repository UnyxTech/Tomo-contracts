// SPDX-License-Identifier: MIT

pragma solidity ^0.8.12;


import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/Tomo.sol";

contract TomoTest is Test {
    Tomo public app;

    bytes32 ZERO_BYTES32 = keccak256("0x0000000000000000000000000000000000000000000000000000000000000000");

    uint256 internal PrivKeyA = 0xAAAAAAAAA;
    uint256 internal PrivKeyB = 0xBBBBBBBBB;
    uint256 internal PrivKeySigner = 0xABCDEF;

    address internal UserA;
    address internal UserB;
    
    address internal signer;
    address[] public signatures;

    function setUp() public {
        UserA = vm.addr(PrivKeyA);
        UserB = vm.addr(PrivKeyB);
        signer = vm.addr(PrivKeySigner);

        signatures.push(signer);
        app = new Tomo(signatures);
    }

    receive() external payable {}

    function testSigners() public {
        bytes32 subject = keccak256(bytes("tiktok/@test"));

        assertEq(app.signers(0), signer);
        assertEq(app.authorized(signer), true);
        assertEq(app.indexes(signer), 0);
    
        address signer1 = address(1);
        address signer2 = address(2);

        app.addSigner(signer1);
        assertEq(app.signers(1), signer1);
        assertEq(app.authorized(signer1), true);
        assertEq(app.indexes(signer1), 1);

        app.addSigner(signer2);
        assertEq(app.signers(2), signer2);
        assertEq(app.authorized(signer2), true);
        assertEq(app.indexes(signer2), 2);

        app.removeSigner(signer1);
        assertEq(app.authorized(signer1), false);
        assertEq(app.signers(1), signer2);
        assertEq(app.indexes(signer2), 1);

        bytes32 digest0 = app.buildBindSeparator(subject, UserA);
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(PrivKeySigner, digest0);
        assertEq(ecrecover(digest0, v0, r0, s0), signer);

        bytes32 digest1 = app.buildRewardSeparator(subject, UserA, 1 ether, 0.08 ether, ZERO_BYTES32);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PrivKeySigner, digest1);
        assertEq(ecrecover(digest1, v1, r1, s1), signer);

        bytes32 digest2 = app.buildBuySeparator(subject, UserA, 1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PrivKeySigner, digest2);
        assertEq(ecrecover(digest2, v2, r2, s2), signer);
    }

    function testBuyVotePass() public {
        bytes32 subject = keccak256(bytes("tiktok/@test"));

        uint8[] memory v = new uint8[](1);
        bytes32[] memory r = new bytes32[](1);
        bytes32[] memory s = new bytes32[](1);

        vm.startPrank(UserA);
        uint256 price = app.getBuyPriceAfterFee(subject, 1);
        vm.deal(UserA, price);
        bytes32 digest = app.buildBuySeparator(subject, UserA, 1);
        (v[0], r[0], s[0]) = vm.sign(PrivKeySigner, digest);
        app.buyVotePass{value: price}(subject, 1, v, r, s);
        assertEq(app.getSubjectSupply(subject), 1);
        assertEq(app.getSubjectBalanceOf(subject, UserA), 1);
        vm.stopPrank();

        vm.startPrank(UserB);
        price = app.getBuyPriceAfterFee(subject, 1);
        vm.deal(UserB, price);
        digest = app.buildBuySeparator(subject, UserB, 1);
        (v[0], r[0], s[0]) = vm.sign(PrivKeyB, digest);
        vm.expectRevert("Invalid signer");
        app.buyVotePass{value: price}(subject, 1, v, r, s);
        assertEq(app.getSubjectSupply(subject), 1);
        assertEq(app.getSubjectBalanceOf(subject, UserB), 0);
        vm.stopPrank();
    }

    function testBindSubject() public {
        bytes32 subject = keccak256(bytes("tiktok/@test"));

        uint8[] memory v = new uint8[](1);
        bytes32[] memory r = new bytes32[](1);
        bytes32[] memory s = new bytes32[](1);

        vm.startPrank(UserA);
        bytes32 digest = app.buildBindSeparator(subject, UserA);
        (v[0], r[0], s[0]) = vm.sign(PrivKeyA, digest);
        vm.expectRevert("Invalid signer");
        app.bindSubjectAndClaim(subject, UserA, v, r, s);

        (v[0], r[0], s[0]) = vm.sign(PrivKeySigner, digest);
        app.bindSubjectAndClaim(subject, UserA, v, r, s);
        assertEq(app.getSubjectOwner(subject), UserA);
        vm.stopPrank();
    }

    function testSetSubjectReward() public {
        bytes32 subject = keccak256(bytes("tiktok/@test"));

        uint8[] memory v = new uint8[](1);
        bytes32[] memory r = new bytes32[](1);
        bytes32[] memory s = new bytes32[](1);

        for (uint256 index = 1; index <= 10; index++) {
            address sender = vm.addr(index);
            vm.startPrank(sender);
            uint256 price = app.getBuyPriceAfterFee(subject, 100);
            vm.deal(sender, price);
            bytes32 hash = app.buildBuySeparator(subject, sender, 100);
            (v[0], r[0], s[0]) = vm.sign(PrivKeySigner, hash);
            app.buyVotePass{value: price}(subject, 100, v, r, s);
            vm.stopPrank();
        }

        vm.startPrank(UserA);
        bytes32 digest = app.buildRewardSeparator(subject, UserA, 1 ether, 0.08 ether, ZERO_BYTES32);
        (v[0], r[0], s[0]) = vm.sign(PrivKeyA, digest);
        vm.expectRevert("Invalid signer");
        app.setSubjectReward(subject, UserA, 1 ether, 0.08 ether, ZERO_BYTES32, v, r, s);

        (v[0], r[0], s[0]) = vm.sign(PrivKeySigner, digest);
        app.setSubjectReward(subject, UserA, 1 ether, 0.08 ether, ZERO_BYTES32, v, r, s);
        assertEq(app.getSubjectOwner(subject), UserA);
        assertEq(app.getSubjectTotalReward(subject), 0.08 ether);
        assertEq(app.getSubjectCurrentReward(subject), 0.08 ether);
        assertEq(app.getSubjectMerkleRoot(subject), ZERO_BYTES32);
        assertGt(app.getSubjectDeadline(subject), app.claimedPeriod());

        vm.expectRevert("Initialized");
        app.setSubjectReward(subject, UserA, 1 ether, 0.08 ether, ZERO_BYTES32, v, r, s);
        vm.stopPrank();
    }

    function testSellVotePass() public {
        bytes32 subject = keccak256(bytes("tiktok/@test"));

        uint8[] memory v = new uint8[](1);
        bytes32[] memory r = new bytes32[](1);
        bytes32[] memory s = new bytes32[](1);
        
        vm.startPrank(UserA);
        uint256 price = app.getBuyPriceAfterFee(subject, 1);
        vm.deal(UserA, price);
        bytes32 digest = app.buildBuySeparator(subject, UserA, 1);
        (v[0], r[0], s[0]) = vm.sign(PrivKeySigner, digest);
        app.buyVotePass{value: price}(subject, 1, v, r, s);
        assertEq(app.getSubjectSupply(subject), 1);
        assertEq(app.getSubjectBalanceOf(subject, UserA), 1);

        app.sellVotePass(subject, 1);
        assertEq(app.getSubjectSupply(subject), 0);
        assertEq(app.getSubjectBalanceOf(subject, UserA), 0);
        assertLt(UserA.balance, price);
        
        vm.expectRevert("Insufficient passes");
        app.sellVotePass(subject, 1);
        vm.stopPrank();
    }

    function testPrice() public {
        uint256 interval = 1;
        for (uint256 index = 0; index < 10; index++) {
            uint256 i = index * interval;
            uint256 price = app.getPrice(i, 1);
            console.log("Price", i, price);
        }
        assertEq(app.getPrice(0, 1), 23057412958266);
        assertEq(app.getPrice(1, 1), 92229651833064);
        assertEq(app.getPrice(5, 1), 830066866497578);
        assertEq(app.getPrice(10, 1), 2789946967950195);
        assertEq(app.getPrice(15, 1), 5902697717316117);
        assertEq(app.getPrice(20, 1), 10168319114595342);
    }
}
