#ifndef PARAMS_H
#define PARAMS_H

#ifndef MASKING_ORDER
#define MASKING_ORDER 3
#endif

#define MAX_ORDER 10      // Optional upper bound for static arrays, sanity checks, etc.

#define NROUNDS 24
#define MASKING_N (MASKING_ORDER + 1)

//  Keccak/SHAKE rate constants
#define KECCAK_RATE 168
#define SHAKE128_RATE 168     // Used for SHAKE128
#define SHAKE256_RATE 136     // Used for SHAKE256
#define SHA3_256_RATE 136     // Same as SHAKE256
#define SHA3_512_RATE 72      // Used for SHA3-512

//Sha and shake domain seperators
#define DOMAIN_SHA3   0x06
#define DOMAIN_SHAKE  0x1F

#endif // PARAMS_H
