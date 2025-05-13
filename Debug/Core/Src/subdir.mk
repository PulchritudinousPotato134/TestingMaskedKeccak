################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (13.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core/Src/debug_log.c \
../Core/Src/fips202.c \
../Core/Src/keccak.c \
../Core/Src/main.c \
../Core/Src/maskedKeccak.c \
../Core/Src/masked_absorb.c \
../Core/Src/masked_gadgets.c \
../Core/Src/masked_keccak_f1600.c \
../Core/Src/masked_sha3_512.c \
../Core/Src/masked_squeeze.c \
../Core/Src/stm32f4xx_hal_msp.c \
../Core/Src/stm32f4xx_it.c \
../Core/Src/syscalls.c \
../Core/Src/sysmem.c \
../Core/Src/system_stm32f4xx.c \
../Core/Src/test_masked_keccak.c 

OBJS += \
./Core/Src/debug_log.o \
./Core/Src/fips202.o \
./Core/Src/keccak.o \
./Core/Src/main.o \
./Core/Src/maskedKeccak.o \
./Core/Src/masked_absorb.o \
./Core/Src/masked_gadgets.o \
./Core/Src/masked_keccak_f1600.o \
./Core/Src/masked_sha3_512.o \
./Core/Src/masked_squeeze.o \
./Core/Src/stm32f4xx_hal_msp.o \
./Core/Src/stm32f4xx_it.o \
./Core/Src/syscalls.o \
./Core/Src/sysmem.o \
./Core/Src/system_stm32f4xx.o \
./Core/Src/test_masked_keccak.o 

C_DEPS += \
./Core/Src/debug_log.d \
./Core/Src/fips202.d \
./Core/Src/keccak.d \
./Core/Src/main.d \
./Core/Src/maskedKeccak.d \
./Core/Src/masked_absorb.d \
./Core/Src/masked_gadgets.d \
./Core/Src/masked_keccak_f1600.d \
./Core/Src/masked_sha3_512.d \
./Core/Src/masked_squeeze.d \
./Core/Src/stm32f4xx_hal_msp.d \
./Core/Src/stm32f4xx_it.d \
./Core/Src/syscalls.d \
./Core/Src/sysmem.d \
./Core/Src/system_stm32f4xx.d \
./Core/Src/test_masked_keccak.d 


# Each subdirectory must supply rules for building sources it contributes
Core/Src/%.o Core/Src/%.su Core/Src/%.cyclo: ../Core/Src/%.c Core/Src/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32F407xx -c -I../USB_HOST/App -I../USB_HOST/Target -I../Core/Inc -I../Drivers/STM32F4xx_HAL_Driver/Inc -I../Drivers/STM32F4xx_HAL_Driver/Inc/Legacy -I../Middlewares/ST/STM32_USB_Host_Library/Core/Inc -I../Middlewares/ST/STM32_USB_Host_Library/Class/CDC/Inc -I../Drivers/CMSIS/Device/ST/STM32F4xx/Include -I../Drivers/CMSIS/Include -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Core-2f-Src

clean-Core-2f-Src:
	-$(RM) ./Core/Src/debug_log.cyclo ./Core/Src/debug_log.d ./Core/Src/debug_log.o ./Core/Src/debug_log.su ./Core/Src/fips202.cyclo ./Core/Src/fips202.d ./Core/Src/fips202.o ./Core/Src/fips202.su ./Core/Src/keccak.cyclo ./Core/Src/keccak.d ./Core/Src/keccak.o ./Core/Src/keccak.su ./Core/Src/main.cyclo ./Core/Src/main.d ./Core/Src/main.o ./Core/Src/main.su ./Core/Src/maskedKeccak.cyclo ./Core/Src/maskedKeccak.d ./Core/Src/maskedKeccak.o ./Core/Src/maskedKeccak.su ./Core/Src/masked_absorb.cyclo ./Core/Src/masked_absorb.d ./Core/Src/masked_absorb.o ./Core/Src/masked_absorb.su ./Core/Src/masked_gadgets.cyclo ./Core/Src/masked_gadgets.d ./Core/Src/masked_gadgets.o ./Core/Src/masked_gadgets.su ./Core/Src/masked_keccak_f1600.cyclo ./Core/Src/masked_keccak_f1600.d ./Core/Src/masked_keccak_f1600.o ./Core/Src/masked_keccak_f1600.su ./Core/Src/masked_sha3_512.cyclo ./Core/Src/masked_sha3_512.d ./Core/Src/masked_sha3_512.o ./Core/Src/masked_sha3_512.su ./Core/Src/masked_squeeze.cyclo ./Core/Src/masked_squeeze.d ./Core/Src/masked_squeeze.o ./Core/Src/masked_squeeze.su ./Core/Src/stm32f4xx_hal_msp.cyclo ./Core/Src/stm32f4xx_hal_msp.d ./Core/Src/stm32f4xx_hal_msp.o ./Core/Src/stm32f4xx_hal_msp.su ./Core/Src/stm32f4xx_it.cyclo ./Core/Src/stm32f4xx_it.d ./Core/Src/stm32f4xx_it.o ./Core/Src/stm32f4xx_it.su ./Core/Src/syscalls.cyclo ./Core/Src/syscalls.d ./Core/Src/syscalls.o ./Core/Src/syscalls.su ./Core/Src/sysmem.cyclo ./Core/Src/sysmem.d ./Core/Src/sysmem.o ./Core/Src/sysmem.su ./Core/Src/system_stm32f4xx.cyclo ./Core/Src/system_stm32f4xx.d ./Core/Src/system_stm32f4xx.o ./Core/Src/system_stm32f4xx.su ./Core/Src/test_masked_keccak.cyclo ./Core/Src/test_masked_keccak.d ./Core/Src/test_masked_keccak.o ./Core/Src/test_masked_keccak.su

.PHONY: clean-Core-2f-Src

