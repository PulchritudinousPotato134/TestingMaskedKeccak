#ifndef GLOBAL_RNG_H
#define GLOBAL_RNG_H

#include "stm32f4xx_hal.h"
#include <stdint.h>

uint64_t get_random64(void);
// Declare hrng as external so other files can use it
extern RNG_HandleTypeDef hrng;

#endif
