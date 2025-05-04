#ifndef PARAMS_H
#define PARAMS_H

// ====================
// 🔐 Masking Parameters
// ====================
#ifndef MASKING_ORDER
#define MASKING_ORDER 3  // Default to 3rd-order masking; override via compiler flag
#endif

#define MAX_ORDER 10      // Optional upper bound for static arrays, sanity checks, etc.

//The minimum number of bits needed to represent a coefficient is ceil(log2(3329)) = 12
#define COEF_NBITS 12



#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64 - offset)))
#define KECCAK_NWORDS 25
#define Plen 200

#define MASKED_CBD_BYTES (KYBER_ETA2 * KYBER_N / 4)
#define MASKING_N (MASKING_ORDER + 1)
//=====================
//  Keccak/SHAKE rate constants
//
#define SHAKE128_RATE 168     // Used for SHAKE128, Kyber XOF
#define SHAKE256_RATE 136     // Used for SHAKE256 (e.g., PRF, hashing)
#define SHA3_256_RATE 136     // Same as SHAKE256
#define SHA3_512_RATE 72      // Used for SHA3-512

#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16
// ====================
//  Kyber Parameters (Kyber768)
// ====================

#define MASKING_N (MASKING_ORDER + 1)

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_K 3  // Kyber768 = k=3

#define KYBER_SYMBYTES 32   // Size in bytes of hashes, seeds, etc.
#define KYBER_SSBYTES  32   // Size of shared secret

#define KYBER_ETA1 2
#define KYBER_ETA2 2

#define KYBER_POLYBYTES 384
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)

#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2 * KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

#endif // PARAMS_H
