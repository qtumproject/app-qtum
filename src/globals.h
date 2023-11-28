#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "ux.h"

#include "kernel/io.h"
#include "commands.h"
#include "constants.h"

/**
 * Global buffer for interactions between SE and MCU.
 */
extern uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

/**
 * Global variable with the length of APDU response to send back.
 */
extern uint16_t G_output_len;

/**
 * Global structure to perform asynchronous UX aside IO operations.
 */
extern ux_state_t G_ux;

/**
 * Global structure with the parameters to exchange with the BOLOS UX application.
 */
extern bolos_ux_params_t G_ux_params;

#define N_storage (*(volatile internalStorage_t *) PIC(&N_storage_real))
typedef struct internalStorage_t {
    bool dataAllowed;
    bool initialized;
} internalStorage_t;

/**
 * Global structure for settings storage.
 */
extern const internalStorage_t N_storage_real;
