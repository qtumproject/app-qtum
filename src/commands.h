#pragma once

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_EXTENDED_PUBKEY = 0x00,
    REGISTER_WALLET = 0x02,
    GET_WALLET_ADDRESS = 0x03,
    SIGN_PSBT = 0x04,
    GET_MASTER_FINGERPRINT = 0x05,
    SIGN_MESSAGE = 0x10,
    SIGN_SENDER_PSBT = 0x81,
} command_e;
