// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OffchainHarness {
    error TooManyTopics();
    error TargetCallFailed();

    function eoca(
        address target,
        bytes calldata callData,
        bytes32 topic0,
        bytes32[] calldata extraTopics,
        bytes calldata data,
        bool requireSuccess
    ) external payable returns (bool ok, bytes memory ret) {
        (ok, ret) = target.call{value: msg.value}(callData);
        if (requireSuccess && !ok) revert TargetCallFailed();
        _emitLog(topic0, extraTopics, data);
    }

    function esda(
        bytes32 topic0,
        bytes32[] calldata extraTopics,
        bytes calldata data
    ) external {
        _emitLog(topic0, extraTopics, data);
    }

    function _emitLog(bytes32 topic0, bytes32[] calldata extraTopics, bytes calldata data) internal {
        uint256 extraLen = extraTopics.length;
        if (extraLen > 3) revert TooManyTopics();

        bytes memory mem = data;
        bytes32 t1;
        bytes32 t2;
        bytes32 t3;
        if (extraLen > 0) t1 = extraTopics[0];
        if (extraLen > 1) t2 = extraTopics[1];
        if (extraLen > 2) t3 = extraTopics[2];

        uint256 len = mem.length;
        assembly {
            let ptr := add(mem, 32)
            switch extraLen
            case 0 { log1(ptr, len, topic0) }
            case 1 { log2(ptr, len, topic0, t1) }
            case 2 { log3(ptr, len, topic0, t1, t2) }
            case 3 { log4(ptr, len, topic0, t1, t2, t3) }
        }
    }
}
