// SPDX-License-Identifier: MIT

pragma solidity ^0.8.12;


library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProofCalldata(proof, leaf) == root;
    }

    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    function processProofCalldata(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    function multiProofVerify(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProof(proof, proofFlags, leaves) == root;
    }

    function multiProofVerifyCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProofCalldata(proof, proofFlags, leaves) == root;
    }

    function processMultiProof(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        uint256 leavesLen = leaves.length;
        uint256 proofLen = proof.length;
        uint256 totalHashes = proofFlags.length;

        require(leavesLen + proofLen - 1 == totalHashes, "MerkleProof: invalid multiproof");

        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i]
                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])
                : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            require(proofPos == proofLen, "MerkleProof: invalid multiproof");
            unchecked {
                return hashes[totalHashes - 1];
            }
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return proof[0];
        }
    }

    function processMultiProofCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        uint256 leavesLen = leaves.length;
        uint256 proofLen = proof.length;
        uint256 totalHashes = proofFlags.length;

        require(leavesLen + proofLen - 1 == totalHashes, "MerkleProof: invalid multiproof");

        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i]
                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])
                : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            require(proofPos == proofLen, "MerkleProof: invalid multiproof");
            unchecked {
                return hashes[totalHashes - 1];
            }
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return proof[0];
        }
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}


abstract contract Ownable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _transferOwnership(msg.sender);
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    function _checkOwner() internal view virtual {
        require(owner() == msg.sender, "Ownable: caller is not the owner");
    }

    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        _status = _NOT_ENTERED;
    }

    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == _ENTERED;
    }
}

contract Tomo is Ownable, ReentrancyGuard {

    bytes32 private constant DOMAIN_NAME = keccak256("Tomo");
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant BIND_TYPEHASH = keccak256(abi.encodePacked("Bind(bytes32 subject,address owner)"));
    bytes32 public constant REWARD_TYPEHASH = keccak256(abi.encodePacked("Reward(bytes32 subject,address owner,uint256 snapshotReward,uint256 rewardPercent,bytes32 merkleRoot)"));
    bytes32 public constant BUY_TYPEHASH = keccak256(abi.encodePacked("Buy(bytes32 subject,address sender,uint256 amount)"));
    bytes32 public DOMAIN_SEPARATOR;

    struct VotePass {
        address owner;
        uint256 totalReward;
        uint256 currentReward;
        bytes32 merkleRoot;
        uint256 deadline;
        uint256 subjectETHBalance;
        uint256 totalSupply;
        mapping (address => uint256) balanceOf;
        mapping (uint256 => uint256) claimedBitMap;
    }

    struct TradeEvent {
        uint256 eventIndex;
        uint256 ts;
        address trader;
        bytes32 subject;
        bool isBuy;
        uint256 buyAmount;
        uint256 ethAmount;
        uint256 traderBalance;
        uint256 supply;
        uint256 totalReward;
    }

    struct ClaimEvent {
        uint256 eventIndex;
        uint256 ts;
        address sender;
        bytes32 subject;
        uint256 claimedIndex;
        uint256 reward;
    }

    struct SubjectRewardSetEvent {
        uint256 eventIndex;
        uint256 ts;
        bytes32 subject;
        address owner;
        uint256 snapshotReward;
        uint256 rewardPercent;
        uint256 totalReward;
    }

    address public protocolFeeTo;
    uint256 public tradeIndex;
    uint256 public bindIndex;
    uint256 public prizeIndex;
    uint256 public claimIndex;
    uint256 public protocolFeePercent;
    uint256 public subjectFeePercent;
    uint256 public rewardFeePercent;
    uint256 public totalReward;
    uint256 public claimedPeriod;
    address[] public signers;
    mapping (address => bool) public authorized;
    mapping (address => uint256) public indexes;
    mapping (bytes32 => VotePass) public votePasses;

    event SignerAdded(address sender, address account);
    event SignerRemoved(address sender, address account);
    event BindSubject(uint256 eventIndex, uint256 ts, bytes32 subject, address owner);
    event RewardClaimed(ClaimEvent claimEvent);
    event SubjectRewardSet(SubjectRewardSetEvent rewardEvent);
    event Trade(TradeEvent tradeEvent);

    constructor(address[] memory array) {
        for (uint256 i = 0; i < array.length; i++) {
            address signer = array[i];
            require(!authorized[signer], "Duplicate existence");
            signers.push(signer);
            authorized[signer] = true;
            indexes[signer] = i;
        }

        protocolFeeTo = msg.sender;
        protocolFeePercent = 0.03 ether; // 3%
        subjectFeePercent = 0.04 ether; // 4%
        rewardFeePercent = 0.03 ether; // 3%
        claimedPeriod = 3 days;

        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        DOMAIN_SEPARATOR = keccak256(abi.encode(DOMAIN_TYPEHASH, DOMAIN_NAME, keccak256(bytes('1')), chainId, address(this)));
    }

    // ============ external cases ============

    struct TradeParameters {
        uint256 value;
        uint256 price;
        uint256 protocolFee;
        uint256 subjectFee;
        uint256 rewardFee;
        bool success;
    }

    function buyVotePass(
        bytes32 subject,
        uint256 amount,
        uint8[] calldata v,
        bytes32[] calldata r,
        bytes32[] calldata s
    ) external payable nonReentrant {
        recover(buildBuySeparator(subject, msg.sender, amount), v, r, s);
        TradeParameters memory params;
        VotePass storage vp = votePasses[subject];
        params.price = getPrice(vp.totalSupply, amount);
        params.protocolFee = params.price * protocolFeePercent / 1 ether;
        params.subjectFee = params.price * subjectFeePercent / 1 ether;
        params.rewardFee = params.price * rewardFeePercent / 1 ether;
        params.value = params.price + params.protocolFee + params.subjectFee + params.rewardFee;
        require(msg.value >= params.value, "Insufficient payment");
        vp.balanceOf[msg.sender] += amount;
        vp.totalSupply += amount;
        totalReward += params.rewardFee;

        if (vp.owner == address(0)) {
            vp.subjectETHBalance += params.subjectFee;
        } else {
            (params.success, ) = vp.owner.call{value: params.subjectFee}(new bytes(0));
            require(params.success, "Unable to send funds");
        }
        (params.success, ) = protocolFeeTo.call{value: params.protocolFee}(new bytes(0));
        require(params.success, "Unable to send funds");

        emit Trade(TradeEvent({
            eventIndex: tradeIndex++,
            ts: block.timestamp,
            trader: msg.sender,
            subject: subject,
            isBuy: true,
            buyAmount: amount,
            ethAmount: params.price,
            traderBalance: vp.balanceOf[msg.sender],
            supply: vp.totalSupply,
            totalReward: totalReward
        }));
    }

    function sellVotePass(
        bytes32 subject,
        uint256 amount
    ) external nonReentrant {
        TradeParameters memory params;
        VotePass storage vp = votePasses[subject];
        require(vp.balanceOf[msg.sender] >= amount, "Insufficient passes");
        params.price = getPrice(vp.totalSupply - amount, amount);
        params.protocolFee = params.price * protocolFeePercent / 1 ether;
        params.subjectFee = params.price * subjectFeePercent / 1 ether;
        params.rewardFee = params.price * rewardFeePercent / 1 ether;
        params.value = params.price - params.protocolFee - params.subjectFee - params.rewardFee;
        vp.balanceOf[msg.sender] -= amount;
        vp.totalSupply -= amount;
        totalReward += params.rewardFee;
        if (vp.owner == address(0)) {
            vp.subjectETHBalance += params.subjectFee;
        } else {
            (params.success, ) = vp.owner.call{value: params.subjectFee}(new bytes(0));
            require(params.success, "Unable to send funds");
        }
        (params.success, ) = msg.sender.call{value: params.value}(new bytes(0));
        require(params.success, "Unable to send funds");
        (params.success, ) = protocolFeeTo.call{value: params.protocolFee}(new bytes(0));
        require(params.success, "Unable to send funds");

        emit Trade(TradeEvent({
            eventIndex: tradeIndex++,
            ts: block.timestamp,
            trader: msg.sender,
            subject: subject,
            isBuy: false,
            buyAmount: amount,
            ethAmount: params.price,
            traderBalance: vp.balanceOf[msg.sender],
            supply: vp.totalSupply,
            totalReward: totalReward
        }));
    }

    function claimReward(
        bytes32 subject,
        uint256 claimedIndex,
        address sender,
        uint256 snapshotBalance,
        uint256 snapshotSupply,
        bytes32[] calldata merkleProof
    ) external nonReentrant {
        VotePass storage vp = votePasses[subject];
        require(block.timestamp <= vp.deadline, "Expire");
        require(!isClaimed(subject, claimedIndex), "Claimed");

        bytes32 node = keccak256(abi.encodePacked(subject, claimedIndex, sender, snapshotBalance, snapshotSupply));
        require(MerkleProof.verify(merkleProof, vp.merkleRoot, node), "Invalid proof");

        uint256 claimedWordIndex = claimedIndex / 256;
        uint256 claimedBitIndex = claimedIndex % 256;
        vp.claimedBitMap[claimedWordIndex] = vp.claimedBitMap[claimedWordIndex] | (1 << claimedBitIndex);

        uint256 reward = vp.totalReward * snapshotBalance / snapshotSupply;
        vp.currentReward -= reward;
        (bool success, ) = sender.call{value: reward}(new bytes(0));
        require(success, "Unable to send funds");

        emit RewardClaimed(ClaimEvent({
            eventIndex: claimIndex++,
            ts: block.timestamp,
            sender: sender,
            subject: subject,
            claimedIndex: claimedIndex,
            reward: reward
        }));
    }

    function setSubjectReward(
        bytes32 subject,
        address owner,
        uint256 snapshotReward,
        uint256 rewardPercent,
        bytes32 merkleRoot,
        uint8[] calldata v,
        bytes32[] calldata r,
        bytes32[] calldata s
    ) external nonReentrant {
        require(rewardPercent <= 1 ether, "Invalid parameter");
        recover(buildRewardSeparator(subject, owner, snapshotReward, rewardPercent, merkleRoot), v, r, s);

        VotePass storage vp = votePasses[subject];
        require(vp.totalReward == 0, "Initialized");
        if (vp.owner == address(0)) {
            vp.owner = owner;
            emit BindSubject(bindIndex++, block.timestamp, subject, owner);
        }
        vp.totalReward = snapshotReward * rewardPercent / 1 ether;
        vp.currentReward = vp.totalReward;
        vp.merkleRoot = merkleRoot;
        vp.deadline = block.timestamp + claimedPeriod;
        totalReward -= vp.totalReward;

        emit SubjectRewardSet(SubjectRewardSetEvent({
            eventIndex: prizeIndex++,
            ts: block.timestamp,
            subject: subject,
            owner: owner,
            snapshotReward: snapshotReward,
            rewardPercent: rewardPercent,
            totalReward: totalReward
        }));
    }

    function bindSubjectAndClaim(
        bytes32 subject,
        address owner,
        uint8[] calldata v,
        bytes32[] calldata r,
        bytes32[] calldata s
    ) external nonReentrant {
        recover(buildBindSeparator(subject, owner), v, r, s);
        VotePass storage vp = votePasses[subject];
        if (vp.owner == address(0)) {
            vp.owner = owner;
            emit BindSubject(bindIndex++, block.timestamp, subject, owner);
        }
        if (vp.subjectETHBalance > 0) {
            uint256 balance = vp.subjectETHBalance;
            vp.subjectETHBalance = 0;
            (bool success, ) = owner.call{value: balance}(new bytes(0));
            require(success, "Unable to send funds");
            emit RewardClaimed(ClaimEvent({
                eventIndex: claimIndex++,
                ts: block.timestamp,
                sender: owner,
                subject: subject,
                claimedIndex: 0,
                reward: balance
            }));
        }
    }

    function addSigner(address account) external onlyOwner {
        require(!authorized[account], "Not reentrant");
        indexes[account] = signers.length;
        authorized[account] = true;
        signers.push(account);
        emit SignerAdded(msg.sender, account);
    }

    function removeSigner(address account) external onlyOwner {
        require(authorized[account], "Non existent");
        require(indexes[account] < signers.length, "Index out of range");

        uint256 index = indexes[account];
        uint256 lastIndex = signers.length - 1;

        if (index != lastIndex) {
            address lastAddr = signers[lastIndex];
            signers[index] = lastAddr;
            indexes[lastAddr] = index;
        }

        delete authorized[account];
        delete indexes[account];
        signers.pop();

        emit SignerRemoved(msg.sender, account);
    }

    function setProtocolFeeTo(address feeTo) external onlyOwner {
        protocolFeeTo = feeTo;
    }

    function setProtocolFeePercent(uint256 feePercent) external onlyOwner {
        protocolFeePercent = feePercent;
    }

    function setSubjectFeePercent(uint256 feePercent) external onlyOwner {
        subjectFeePercent = feePercent;
    }

    function setRewardFeePercent(uint256 feePercent) external onlyOwner {
        rewardFeePercent = feePercent;
    }

    function setClaimedPeriod(uint256 period) external onlyOwner {
        claimedPeriod = period;
    }

    function setSubjectMerkleRoot(bytes32 subject, bytes32 merkleRoot) external onlyOwner {
        require(votePasses[subject].currentReward > 0, "Insufficient rewards");
        votePasses[subject].merkleRoot = merkleRoot;
        if (votePasses[subject].deadline < block.timestamp) {
            votePasses[subject].deadline = block.timestamp + claimedPeriod;
        }
    }

    // ============ view cases ============

    function recover(
        bytes32 hash,
        uint8[] calldata v,
        bytes32[] calldata r,
        bytes32[] calldata s
    ) public view returns (bool) {
        uint256 length = signers.length;
        require(length > 0 && length == v.length && length == r.length && length == s.length, "Invalid signature length");
        address[] memory signatures = new address[](length);
        for (uint256 i = 0; i < length; i++) {
            address signer = ecrecover(hash, v[i], r[i], s[i]);
            require(authorized[signer], "Invalid signer");
            for (uint256 j = 0; j < i; j++) {
                require(signatures[j] != signer, "Duplicated");
            }
            signatures[i] = signer;
        }
        return true;
    }

    function getPrice(uint256 supply, uint256 amount) public pure returns (uint256) {
        uint256 sum1 = supply * (supply + 1) * (2 * supply + 1) / 6;
        uint256 sum2 = (supply + amount) * (supply + 1 + amount) * (2 * (supply + amount) + 1) / 6;
        uint256 summation = sum2 - sum1;
        return summation * 1 ether / 43370;
    }

    function getBuyPrice(bytes32 subject, uint256 amount) public view returns (uint256) {
        return getPrice(votePasses[subject].totalSupply, amount);
    }

    function getSellPrice(bytes32 subject, uint256 amount) public view returns (uint256) {
        return getPrice(votePasses[subject].totalSupply - amount, amount);
    }

    function getBuyPriceAfterFee(bytes32 subject, uint256 amount) public view returns (uint256) {
        uint256 price = getBuyPrice(subject, amount);
        uint256 protocolFee = price * protocolFeePercent / 1 ether;
        uint256 subjectFee = price * subjectFeePercent / 1 ether;
        uint256 rewardFee = price * rewardFeePercent / 1 ether;
        return price + protocolFee + subjectFee + rewardFee;
    }

    function getSellPriceAfterFee(bytes32 subject, uint256 amount) public view returns (uint256) {
        uint256 price = getSellPrice(subject, amount);
        uint256 protocolFee = price * protocolFeePercent / 1 ether;
        uint256 subjectFee = price * subjectFeePercent / 1 ether;
        uint256 rewardFee = price * rewardFeePercent / 1 ether;
        return price - protocolFee - subjectFee - rewardFee;
    }

    function getSubjectOwner(bytes32 subject) public view returns (address) {
        return votePasses[subject].owner;
    }

    function getSubjectETHBalance(bytes32 subject) public view returns (uint256) {
        return votePasses[subject].subjectETHBalance;
    }

    function getSubjectSupply(bytes32 subject) public view returns (uint256) {
        return votePasses[subject].totalSupply;
    }

    function getSubjectBalanceOf(bytes32 subject, address account) public view returns (uint256) {
        return votePasses[subject].balanceOf[account];
    }

    function getSubjectTotalReward(bytes32 subject) public view returns (uint256) {
        return votePasses[subject].totalReward;
    }

    function getSubjectCurrentReward(bytes32 subject) public view returns (uint256) {
        return votePasses[subject].currentReward;
    }

    function getSubjectMerkleRoot(bytes32 subject) public view returns (bytes32) {
        return votePasses[subject].merkleRoot;
    }

    function getSubjectDeadline(bytes32 subject) public view returns (uint256) {
        return votePasses[subject].deadline;
    }

    function isClaimed(bytes32 subject, uint256 index) public view returns (bool) {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = votePasses[subject].claimedBitMap[claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    function buildBindSeparator(
        bytes32 subject,
        address owner
    ) view public returns (bytes32) {
        return keccak256(abi.encodePacked(
            '\x19\x01',
            DOMAIN_SEPARATOR,  
            keccak256(abi.encode(BIND_TYPEHASH, subject, owner))
        ));
    }

    function buildRewardSeparator(
        bytes32 subject,
        address owner,
        uint256 snapshotReward,
        uint256 rewardPercent,
        bytes32 merkleRoot
    ) view public returns (bytes32) {
        return keccak256(abi.encodePacked(
            '\x19\x01',
            DOMAIN_SEPARATOR,  
            keccak256(abi.encode(REWARD_TYPEHASH, subject, owner, snapshotReward, rewardPercent, merkleRoot))
        ));
    }

    function buildBuySeparator(
        bytes32 subject,
        address sender,
        uint256 amount
    ) view public returns (bytes32) {
        return keccak256(abi.encodePacked(
            '\x19\x01',
            DOMAIN_SEPARATOR,  
            keccak256(abi.encode(BUY_TYPEHASH, subject, sender, amount))
        ));
    }
}