#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

#include "stm32f4xx_hal.h"
#include <stdint.h>
#include <stdarg.h>

// Externally defined UART handle (e.g., in main.c or usart.c)
extern UART_HandleTypeDef huart2;

// Log function that works like printf, using UART
void debug_log(const char *fmt, ...);

#endif // DEBUG_LOG_H
