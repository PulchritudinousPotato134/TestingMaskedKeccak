#include "stm32f4xx_hal.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "debug_log.h"
extern UART_HandleTypeDef huart2;

void debug_log(const char *fmt, ...) {
    char buf[128];  // Adjust size as needed
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    HAL_UART_Transmit(&huart2, (uint8_t*)buf, strlen(buf), HAL_MAX_DELAY);
}
