#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "../common/bip32.h"
#include "../common/buffer.h"
#include "../common/read.h"
#include "../common/script.h"
#include "../common/segwit_addr.h"

#ifndef SKIP_FOR_CMOCKA
#include "../crypto.h"
#endif

size_t get_push_script_size(uint32_t n) {
    if (n <= 16)
        return 1;  // OP_0 and OP_1 .. OP_16
    else if (n < 0x80)
        return 2;  // 01 nn
    else if (n < 0x8000)
        return 3;  // 02 nnnn
    else if (n < 0x800000)
        return 4;  // 03 nnnnnn
    else if (n < 0x80000000)
        return 5;  // 04 nnnnnnnn
    else
        return 6;  // 05 nnnnnnnnnn
}

int get_script_type(const uint8_t script[], size_t script_len) {
    if (script_len == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 0x14 &&
        script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG) {
        return SCRIPT_TYPE_P2PKH;
    }

    if (script_len == 23 && script[0] == OP_HASH160 && script[1] == 0x14 &&
        script[22] == OP_EQUAL) {
        return SCRIPT_TYPE_P2SH;
    }

    if (script_len == 22 && script[0] == 0x00 && script[1] == 0x14) {
        return SCRIPT_TYPE_P2WPKH;
    }

    if (script_len == 34 && script[0] == OP_0 && script[1] == 0x20) {
        return SCRIPT_TYPE_P2WSH;
    }

    if (script_len == 34 && script[0] == OP_1 && script[1] == 0x20) {
        return SCRIPT_TYPE_P2TR;
    }

    // match if it is a potentially valid future segwit scriptPubKey as per BIP-0141
    if (script_len >= 4 && script_len <= 42 &&
        (script[0] == 0 || (script[0] >= OP_1 && script[0] <= OP_16))) {
        uint8_t push_len = script[1];
        if (script_len == 1 + 1 + push_len) {
            return SCRIPT_TYPE_UNKNOWN_SEGWIT;
        }
    }

    // unknown/invalid, or doesn't have an address
    return -1;
}

#ifndef SKIP_FOR_CMOCKA

// TODO: add unit tests
int get_script_address(const uint8_t script[], size_t script_len, char *out, size_t out_len) {
    int script_type = get_script_type(script, script_len);
    int addr_len;
    switch (script_type) {
        case SCRIPT_TYPE_P2PKH:
        case SCRIPT_TYPE_P2SH: {
            int offset = (script_type == SCRIPT_TYPE_P2PKH) ? 3 : 2;
            int ver = (script_type == SCRIPT_TYPE_P2PKH) ? COIN_P2PKH_VERSION : COIN_P2SH_VERSION;
            addr_len = base58_encode_address(script + offset, ver, out, out_len - 1);
            if (addr_len < 0) {
                return -1;
            }
            break;
        }
        case SCRIPT_TYPE_P2WPKH:
        case SCRIPT_TYPE_P2WSH:
        case SCRIPT_TYPE_P2TR:
        case SCRIPT_TYPE_UNKNOWN_SEGWIT: {
            uint8_t prog_len = script[1];  // length of the witness program

            // witness program version
            int version = (script[0] == 0 ? 0 : script[0] - 80);

            // make sure that the output buffer is long enough
            if (out_len < 73 + strlen(COIN_NATIVE_SEGWIT_PREFIX)) {
                return -1;
            }

            int ret =
                segwit_addr_encode(out, COIN_NATIVE_SEGWIT_PREFIX, version, script + 2, prog_len);

            if (ret != 1) {
                return -1;  // should never happen
            }

            addr_len = strlen(out);
            break;
        }
        default:
            return -1;
    }
    if (addr_len >= 0) {
        out[addr_len] = '\0';
    }
    return addr_len;
}

#endif

int format_opscript_script(const uint8_t script[],
                           size_t script_len,
                           char out[static MAX_OPRETURN_OUTPUT_DESC_SIZE]) {
    if (script_len == 0 || script[0] != OP_RETURN) {
        return -1;
    }

    strcpy(out, "OP_RETURN ");
    int out_ctr = 10;

    uint8_t opcode = script[1];  // the push opcode
    if (opcode > OP_16 || opcode == OP_RESERVED || opcode == OP_PUSHDATA2 ||
        opcode == OP_PUSHDATA4) {
        return -1;  // unsupported
    }

    int hex_offset = 1;
    size_t hex_length =
        0;  // if non-zero, `hex_length` bytes starting from script[hex_offset] must be hex-encoded

    if (opcode == OP_0) {
        if (script_len != 1 + 1) return -1;
        out[out_ctr++] = '0';
    } else if (opcode >= 1 && opcode <= 75) {
        hex_offset += 1;
        hex_length = opcode;

        if (script_len != 1 + 1 + hex_length) return -1;
    } else if (opcode == OP_PUSHDATA1) {
        // OP_RETURN OP_PUSHDATA1 <len:1-byte> <data:len bytes>
        hex_offset += 2;
        hex_length = script[2];

        if (script_len != 1 + 1 + 1 + hex_length || hex_length > 80) return -1;
    } else if (opcode == OP_1NEGATE) {
        if (script_len != 1 + 1) return -1;

        out[out_ctr++] = '-';
        out[out_ctr++] = '1';
    } else if (opcode >= OP_1 && opcode <= OP_16) {
        if (script_len != 1 + 1) return -1;

        // encode OP_1 to OP_16 as a decimal number
        uint8_t num = opcode - 0x50;
        if (num >= 10) {
            out[out_ctr++] = '0' + (num / 10);
        }
        out[out_ctr++] = '0' + (num % 10);
    } else {
        return -1;  // can never happen
    }

    if (hex_length > 0) {
        const char hex[] = "0123456789abcdef";

        out[out_ctr++] = '0';
        out[out_ctr++] = 'x';
        for (unsigned int i = 0; i < hex_length; i++) {
            uint8_t data = script[hex_offset + i];
            out[out_ctr++] = hex[data / 16];
            out[out_ctr++] = hex[data % 16];
        }
    }

    out[out_ctr++] = '\0';
    return out_ctr;
}

bool get_script_op(uint8_t ** pc, const uint8_t * end, uint8_t* opcodeRet, uint8_t **pvchRet, unsigned int *pvchSize)
{
    *opcodeRet = OP_INVALIDOPCODE;
    if (*pc >= end)
        return 0;

    if(pvchRet)
        *pvchRet = 0;
    if(pvchSize)
        *pvchSize = 0;

    // Read instruction
    if (end - *pc < 1)
        return 0;
    uint8_t opcode = *(*pc)++;

    // Immediate operand
    if (opcode <= OP_PUSHDATA4)
    {
        unsigned int nSize = 0;
        if (opcode < OP_PUSHDATA1)
        {
            nSize = opcode;
        }
        else if (opcode == OP_PUSHDATA1)
        {
            if (end - *pc < 1)
                return 0;
            nSize = *(*pc)++;
        }
        else if (opcode == OP_PUSHDATA2)
        {
            if (end - *pc < 2)
                return 0;

            nSize = read_u16_le(*pc, 0);
            *pc += 2;
        }
        else if (opcode == OP_PUSHDATA4)
        {
            if (end - *pc < 4)
                return 0;
            nSize = read_u32_le(*pc, 0);
            *pc += 4;
        }
        if (end - *pc < 0 || (unsigned int)(end - *pc) < nSize)
            return 0;
        if(pvchRet)
            *pvchRet = *pc;
        if(pvchSize)
            *pvchSize = nSize;
        *pc += nSize;
    }

    *opcodeRet = opcode;
    return 1;
}

bool get_script_size(uint8_t *buffer, size_t maxSize, unsigned int *scriptSize, unsigned int *discardSize) 
{
    *scriptSize = 0;
    *discardSize = 0;
    if (maxSize > 0 && buffer[0] < 0xFD) {
        *scriptSize = buffer[0];
        *discardSize = 1;
    } else if (maxSize > 2 && buffer[0] == 0xFD) {
        *scriptSize = read_u16_le(buffer + 1, 0);
        *discardSize = 3;
    } else {
        return 0;
    }

    size_t bifferSize = *scriptSize + *discardSize;
    if(bifferSize <= maxSize) {
        return 1;
    }

    return 0;
}

// Have script size inside the script
#define HAVE_SCRIPT_SIZE 0

int find_script_op(uint8_t *buffer, size_t size, uint8_t op, bool haveSize)
{
    int nFound = 0;
    unsigned int scriptSize = size;
    unsigned int discardSize = 0;
    if(haveSize)
        get_script_size(buffer, size, &scriptSize, &discardSize);
    uint8_t opcode = OP_INVALIDOPCODE;
    const uint8_t* end = buffer + scriptSize + discardSize;
    uint8_t *begin = buffer + discardSize;
    for (uint8_t * pc = begin; pc != end && get_script_op(&pc, end, &opcode, 0, 0);)
        if (opcode == op)
            ++nFound;
    return nFound;
}

bool find_script_data(uint8_t *buffer, size_t size, int index, bool haveSize,  uint8_t **pvchRet, unsigned int *pvchSize)
{
    unsigned int scriptSize = size;
    unsigned int discardSize = 0;
    if(haveSize)
        get_script_size(buffer, size, &scriptSize, &discardSize);
    uint8_t opcode = OP_INVALIDOPCODE;
    const uint8_t* end = buffer + scriptSize + discardSize;
    uint8_t *begin = buffer + discardSize;
    int i = 0;
    for (uint8_t * pc = begin; i < index && pc != end && get_script_op(&pc, end, &opcode, pvchRet, pvchSize); i++);
    return i == index;
}

void get_script_p2pkh(const uint8_t *pkh, uint8_t *script, uint8_t haveSize)
{
    uint8_t offset = haveSize ? 1 : 0;
    if(haveSize) script[0] = 0x19;
    script[0 + offset] = OP_DUP;
    script[1 + offset] = OP_HASH160;
    script[2 + offset] = 0x14;
    memcpy(script + 3 + offset, pkh, 20);
    script[23 + offset] = OP_EQUALVERIFY;
    script[24 + offset] = OP_CHECKSIG;
}

bool is_opcontract(uint8_t script[], size_t script_len, uint8_t value) {
    return (!is_p2wpkh(script, script_len) &&
            !is_p2wsh(script, script_len) &&
            !is_opreturn(script, script_len) &&
            find_script_op(script, script_len, value, HAVE_SCRIPT_SIZE) == 1);
}

bool is_opcreate(uint8_t script[], size_t script_len) {
    return is_opcontract(script, script_len, OP_CREATE);
}

bool is_opcall(uint8_t script[], size_t script_len) {
    return is_opcontract(script, script_len, OP_CALL);
}

bool is_opsender(uint8_t script[], size_t script_len) {
    return is_opcontract(script, script_len, OP_SENDER);
}

bool get_script_sender_address(uint8_t *buffer, size_t size, uint8_t *script) {
    uint8_t *pkh = 0;
    unsigned int pkhSize = 0;
    bool ret = find_script_data(buffer, size, 2, HAVE_SCRIPT_SIZE, &pkh, &pkhSize) == 1 && pkh != 0 && pkhSize == 20;
    if(ret) get_script_p2pkh(pkh, script, HAVE_SCRIPT_SIZE);
    return ret;
}

bool get_sender_sig(uint8_t *buffer, size_t size, uint8_t **sig, unsigned int *sigSize) {
    if(sig == 0 || sigSize == 0)
        return 0;
    return find_script_data(buffer, size, 3, HAVE_SCRIPT_SIZE, sig, sigSize) && *sig != 0 && *sigSize > 0;
}
