# schema: [opcode, ins, outs, gas]
opcodes = {
    0x00: ['STOP', 0, 0],
    0x01: ['ADD', 2, 1],
    0x02: ['MUL', 2, 1],
    0x03: ['SUB', 2, 1],
    0x04: ['DIV', 2, 1],
    0x05: ['SDIV', 2, 1],
    0x06: ['MOD', 2, 1],
    0x07: ['SMOD', 2, 1],
    0x08: ['ADDMOD', 3, 1],
    0x09: ['MULMOD', 3, 1],
    0x0a: ['EXP', 2, 1],
    0x0b: ['SIGNEXTEND', 2, 1],
    0x10: ['LT', 2, 1],
    0x11: ['GT', 2, 1],
    0x12: ['SLT', 2, 1],
    0x13: ['SGT', 2, 1],
    0x14: ['EQ', 2, 1],
    0x15: ['ISZERO', 1, 1],
    0x16: ['AND', 2, 1],
    0x17: ['OR', 2, 1],
    0x18: ['XOR', 2, 1],
    0x19: ['NOT', 1, 1],
    0x1a: ['BYTE', 2, 1],
    0x1b: ['SHL', 2, 1],
    0x1c: ['SHR', 2, 1],
    0x1d: ['SAR', 2, 1],
    0x1e: ['CLZ', 1, 1],
    0x20: ['SHA3', 2, 1],
    0x30: ['ADDRESS', 0, 1],
    0x31: ['BALANCE', 1, 1],  # now 400
    0x32: ['ORIGIN', 0, 1],
    0x33: ['CALLER', 0, 1],
    0x34: ['CALLVALUE', 0, 1],
    0x35: ['CALLDATALOAD', 1, 1],
    0x36: ['CALLDATASIZE', 0, 1],
    0x37: ['CALLDATACOPY', 3, 0],
    0x38: ['CODESIZE', 0, 1],
    0x39: ['CODECOPY', 3, 0],
    0x3a: ['GASPRICE', 0, 1],
    0x3b: ['EXTCODESIZE', 1, 1],  # now 700
    0x3c: ['EXTCODECOPY', 4, 0],  # now 700
    0x3d: ['RETURNDATASIZE', 0, 1],
    0x3e: ['RETURNDATACOPY', 3, 0],
    0x40: ['BLOCKHASH', 1, 1],
    0x41: ['COINBASE', 0, 1],
    0x42: ['TIMESTAMP', 0, 1],
    0x43: ['NUMBER', 0, 1],
    0x44: ['PREVRANDAO', 0, 1],
    0x46: ['CHAINID', 0, 1],
    0x47: ['SELFBALANCE', 0, 1],
    0x48: ['BASEFEE', 0, 1],
    0x49: ['BLOBHASH', 1, 1],
    0x4a: ['BLOBBASEFEE', 0, 1],
    0x50: ['POP', 1, 0],
    0x51: ['MLOAD', 1, 1],
    0x52: ['MSTORE', 2, 0],
    0x53: ['MSTORE8', 2, 0],
    0x54: ['SLOAD', 1, 1],  # 200 now
    0x55: ['SSTORE', 2, 0],  # actual cost 5000-20000 depending on circumstance
    0x56: ['JUMP', 1, 0],
    0x57: ['JUMPI', 2, 0],
    0x58: ['PC', 0, 1],
    0x59: ['MSIZE', 0, 1],
    0x5a: ['GAS', 0, 1],
    0x5b: ['JUMPDEST', 0, 0],
    0x5c: ['TLOAD', 1, 1],
    0x5d: ['TSTORE', 2, 0],
    0x5e: ['MCOPY', 3, 0],
    0x5f: ['PUSH0', 0, 1],
    0xa0: ['LOG0', 2, 0],
    0xa1: ['LOG1', 3, 0],
    0xa2: ['LOG2', 4, 0],
    0xa3: ['LOG3', 5, 0],
    0xa4: ['LOG4', 6, 0],
    0xe1: ['SLOADBYTES', 3, 0],  # to be discontinued
    0xe2: ['SSTOREBYTES', 3, 0],  # to be discontinued
    0xe3: ['SSIZE', 1, 1],  # to be discontinued
    0xf0: ['CREATE', 3, 1],
    0xf1: ['CALL', 7, 1],  # 700 now
    0xf2: ['CALLCODE', 7, 1],  # 700 now
    0xf3: ['RETURN', 2, 0],
    0xf4: ['DELEGATECALL', 6, 1],  # 700 now
    0xf5: ['CREATE2', 4, 1],
    0xfa: ['STATICCALL', 6, 1],
    0xfd: ['REVERT', 2, 0],
    0xfe: ['INVALID', 0, 0],
    0xff: ['SELFDESTRUCT', 1, 0],  # 5000 now
}

for i in range(1, 33):
    opcodes[0x5f + i] = ['PUSH' + str(i), 0, 1]

for i in range(1, 17):
    opcodes[0x7f + i] = ['DUP' + str(i), i, i + 1]
    opcodes[0x8f + i] = ['SWAP' + str(i), i + 1, i + 1]






