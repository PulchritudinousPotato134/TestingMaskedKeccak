#include "maskedKeccak.h"
#include "fips202.h"      // Unmasked Keccak for reference
#include "stm32f4xx_hal.h"
#include <string.h>
#include <stdio.h>

extern RNG_HandleTypeDef hrng;

// === Print utility for UART/semihosting ===
void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s:\n", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

// === Convert scalar input into masked shares ===
void trivial_mask_input(uint8_t *masked_input, const uint8_t *input, size_t len) {
    for (size_t i = 0; i < len; i++) {
        masked_input[i * MASKING_N] = input[i];         // Share 0 = data
        for (size_t j = 1; j < MASKING_N; j++) {
            masked_input[i * MASKING_N + j] = 0;         // Other shares = 0
        }
    }
}

void test_masked_keccak(void) {
	printf("KYBER_K = %d\n", KYBER_K);

    const size_t inlen = 33;
    const size_t outlen = 64;

    uint8_t input[33] = {0};
    input[32] = KYBER_K;

    uint8_t ref_output[64];
    uint8_t masked_output[64 * MASKING_N];
    uint8_t masked_input[33 * MASKING_N];

    // 1. Get reference unmasked hash
    sha3_512(ref_output, input, inlen);


    // === DEBUG: Print input
    print_hex("Input", input, inlen);

    // 2. Prepare masked input
    trivial_mask_input(masked_input, input, inlen);

    // === DEBUG: Print masked input Share[0]
    uint8_t masked_input_share0[33];
    for (size_t i = 0; i < inlen; i++) {
        masked_input_share0[i] = masked_input[i * MASKING_N];
    }
    print_hex("Masked Input Share[0]", masked_input_share0, inlen);

    // 3. Run masked SHA3-512 (not SHAKE256!)
    masked_sha3_512(masked_output,    // [byte][share]
                    1, MASKING_N,     // out_msk_stride, out_data_stride
                    masked_input,
                    inlen,
                    MASKING_N, 1);    // in_msk_stride, in_data_stride


    // 4. Extract and print Share[0] of masked output
    uint8_t first_share[64];
    for (size_t i = 0; i < outlen; i++) {
        first_share[i] = masked_output[i * MASKING_N];
    }

    print_hex("Reference SHA3_512", ref_output, outlen);
    print_hex("Masked Output Share[0]", first_share, outlen);

    // 5. Compare only Share[0] to reference
    if (memcmp(ref_output, first_share, outlen) == 0) {
        printf("\n✅ First share matches reference.\n");
    } else {
        printf("\n❌ First share does NOT match.\n");
    }
}

