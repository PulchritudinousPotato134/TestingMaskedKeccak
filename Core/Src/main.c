/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usb_host.h"
extern const uint64_t RC[24];

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "global_rng.h"
#include <string.h>
#include <stdio.h>
#include "masked_gadgets.h"
#include "keccak.h"
#include "sha_shake.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
I2C_HandleTypeDef hi2c1;

I2S_HandleTypeDef hi2s3;

RNG_HandleTypeDef hrng;

SPI_HandleTypeDef hspi1;

UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_I2C1_Init(void);
static void MX_I2S3_Init(void);
static void MX_SPI1_Init(void);
static void MX_RNG_Init(void);
static void MX_USART2_UART_Init(void);
void MX_USB_HOST_Process(void);

/* USER CODE BEGIN PFP */
int _write(int file, char *ptr, int len) {
    HAL_UART_Transmit(&huart2, (uint8_t*) ptr, len, HAL_MAX_DELAY);
    return len;
}

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void print_masked_hex(const char *label, uint8_t data[64][MASKING_N]) {
    printf("%s: ", label);
    for (int i = 0; i < 64; i++) {
        uint8_t acc = data[i][0];
        for (int j = 1; j < MASKING_N; j++) {
            acc ^= data[i][j];
        }
        printf("%02X", acc);
    }
    printf("\n");
}
void print_u64(uint64_t val) {
    for (int i = 60; i >= 0; i -= 4) {
        uint8_t nibble = (val >> i) & 0xF;
        char c = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
        HAL_UART_Transmit(&huart2, (uint8_t*)&c, 1, HAL_MAX_DELAY);
    }
    char newline = '\n';
    HAL_UART_Transmit(&huart2, (uint8_t*)&newline, 1, HAL_MAX_DELAY);
}

void fill_masked_state(masked_uint64_t dst[5][5], const uint64_t ref[25]) {
    for (int y = 0; y < 5; ++y) {
        for (int x = 0; x < 5; ++x) {
            uint64_t val = ref[y * 5 + x];
            uint64_t t = val;
            for (int i = 1; i < MASKING_N; ++i) {
                dst[x][y].share[i] = get_random64();
                t ^= dst[x][y].share[i];
            }
            dst[x][y].share[0] = t;
        }
    }
}

void recombine_masked_state(uint64_t dst[25], const masked_uint64_t src[5][5]) {
    for (int y = 0; y < 5; ++y)
        for (int x = 0; x < 5; ++x) {
            uint64_t val = 0;
            for (int i = 0; i < MASKING_N; ++i)
                val ^= src[x][y].share[i];
            dst[y * 5 + x] = val;
        }
}

void print_diff(const char *label, const uint64_t *ref, const uint64_t *masked) {
    int fail = 0;
    for (int i = 0; i < 25; ++i) {
        if (ref[i] != masked[i]) {
            uint32_t rh = ref[i] >> 32, rl = ref[i] & 0xFFFFFFFF;
            uint32_t mh = masked[i] >> 32, ml = masked[i] & 0xFFFFFFFF;
            printf("Mismatch %s[%d]: ref = %08lX%08lX, masked = %08lX%08lX\n",
                   label, i,
                   (unsigned long)rh, (unsigned long)rl,
                   (unsigned long)mh, (unsigned long)ml);
            fail++;
        }
    }
    if (fail == 0) {
        printf("SUCCESS: %s output matched reference.\n", label);
    }
}

void test_masked_vs_reference_step_by_step(void) {
    // === 1. Initial state setup ===
    uint64_t ref_state[25];
    for (int i = 0; i < 25; i++)
        ref_state[i] = i * 0x0F0F0F0F0F0F0F0FULL;

    masked_uint64_t masked_state[5][5];
    fill_masked_state(masked_state, ref_state);

    uint64_t tmp_ref[25], tmp_masked[25];

    // === 2. THETA ===
    memcpy(tmp_ref, ref_state, sizeof(ref_state));
    theta(tmp_ref);

    masked_theta(masked_state);
    recombine_masked_state(tmp_masked, masked_state);
    print_diff("THETA", tmp_ref, tmp_masked);

    // === 3. RHO ===
    memcpy(tmp_ref, tmp_masked, sizeof(tmp_masked)); // set ref = masked out
    rho(tmp_ref);

    masked_rho(masked_state);
    recombine_masked_state(tmp_masked, masked_state);
    print_diff("RHO", tmp_ref, tmp_masked);

    // === 4. PI ===
    memcpy(tmp_ref, tmp_masked, sizeof(tmp_masked));
    pi(tmp_ref);

    masked_pi(masked_state);
    recombine_masked_state(tmp_masked, masked_state);
    print_diff("PI", tmp_ref, tmp_masked);

    int round_idx = 0;
    // === 5. CHI ===
    // === 5. CHI ===
    memcpy(tmp_ref, tmp_masked, sizeof(tmp_masked));
    chi(tmp_ref);

    uint64_t r_chi[5][5][MASKING_N][MASKING_N];
    for (int y = 0; y < 5; ++y)
        for (int x = 0; x < 5; ++x)
            fill_random_matrix(r_chi[x][y]);

    masked_uint64_t chi_out[5][5];
    masked_chi(chi_out, masked_state, r_chi);

    // === 6. IOTA ===
    // Apply IOTA to both the reference and the masked CHI result
    iota(tmp_ref, round_idx);
    masked_iota(chi_out, RC[round_idx]);

    // Recombine the masked state AFTER both steps
    recombine_masked_state(tmp_masked, chi_out);

    // Compare both sides now that they're at the same stage
    print_diff("IOTA", tmp_ref, tmp_masked);



}
static void masked_round(masked_uint64_t S[5][5],
                         int r,
                         uint64_t Rchi[5][5][MASKING_N][MASKING_N])
{
    masked_theta(S);
    masked_rho  (S);
    masked_pi   (S);
    uint64_t r_chi[5][5][MASKING_N][MASKING_N];
      for (int y = 0; y < 5; ++y)
          for (int x = 0; x < 5; ++x)
              fill_random_matrix(r_chi[x][y]);

      masked_uint64_t chi_out[5][5];
      masked_chi(chi_out, S, r_chi);
      masked_iota (chi_out, RC[r]);

      for (int y = 0; y < 5; ++y)
          for (int x = 0; x < 5; ++x)
              S[x][y] = chi_out[x][y];
}

static void reference_round(uint64_t *A, int r)
{
    theta(A);
    rho  (A);
    pi   (A);
    chi  (A);
    iota (A, r);
}


void test_full_keccak_rounds(void)
{
    /* --- 1. fresh deterministic state -------------------------------- */
    uint64_t ref[25];
    for (int i=0;i<25;i++)
        ref[i] = 0x1111111111111111ULL * (i+1);   /* any pattern is fine */

    masked_uint64_t mstate[5][5];
    fill_masked_state(mstate, ref);

    /* --- 2. run every round ------------------------------------------ */
    for (int r = 0; r < 24; ++r) {

        /* randomness for χ – new every round, every lane --------------- */
        uint64_t Rchi[5][5][MASKING_N][MASKING_N];
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                fill_random_matrix(Rchi[x][y]);

        reference_round(ref, r);
        masked_round(mstate, r, Rchi);

        uint64_t recon[25];
        recombine_masked_state(recon, mstate);

        /* --- 3. compare lane by lane --------------------------------- */
        int fail = 0;
        for (int i = 0; i < 25; ++i) {
            if (recon[i] != ref[i]) {
                printf("Round %2d lane %2d : ref=%016llX  mask=%016llX\n",
                       r, i,
                       (unsigned long long)ref[i],
                       (unsigned long long)recon[i]);
                fail = 1;
            }
        }
        if (fail) {
            printf("✗ round %d FAILED – stop early\n\n", r);
            return;
        }
    }

    printf("✓ all 24 masked rounds match reference Keccak-F[1600]\n");
}

void test_masked_keccak_round_vs_reference(void) {
    // === 1. Setup known input ===
    uint64_t ref_state[25];
    for (int i = 0; i < 25; i++)
        ref_state[i] = i * 0x0101010101010101ULL;

    masked_uint64_t masked_state[5][5];
    fill_masked_state(masked_state, ref_state);

    uint64_t tmp_ref[25], tmp_masked[25];

    // === 2. Apply reference round ===
    memcpy(tmp_ref, ref_state, sizeof(ref_state));
    theta(tmp_ref);
    rho(tmp_ref);
    pi(tmp_ref);
    chi(tmp_ref);
    iota(tmp_ref, 0);

    // === 3. Apply masked round ===
    masked_keccak_round(masked_state, RC[0]);
    recombine_masked_state(tmp_masked, masked_state);

    // === 4. Compare ===
    print_diff("Keccak-Round", tmp_ref, tmp_masked);
}
extern int TWOFIVESIX(uint8_t* M, int l, uint8_t* O);
extern int FIVEONETWO(uint8_t* M, int l, uint8_t* O);

void test_masked_vs_reference_sha3_256(void) {
    const char *msg = "Masked Keccak Test Vector: SHA3-256";
    size_t len = strlen(msg);

    uint8_t ref_out[32];
    uint8_t masked_out[32];

    // Call reference implementation
    TWOFIVESIX((uint8_t *)msg, (int)len, ref_out);

    // Call masked implementation
    masked_sha3_256(masked_out, (const uint8_t *)msg, len);

    // Compare output
    for (int i = 0; i < 32; ++i) {
        if (ref_out[i] != masked_out[i]) {
            printf("Mismatch SHA3-256 byte[%d]: ref=0x%02X, masked=0x%02X\n",
                   i, ref_out[i], masked_out[i]);
            assert(0);
        }
    }
    printf("PASS: SHA3-256 masked output matches reference\n");
}

void test_masked_vs_reference_sha3_512(void) {
    const char *msg = "Masked Keccak Test Vector: SHA3-512";
    size_t len = strlen(msg);

    uint8_t ref_out[64];
    uint8_t masked_out[64];

    // Call reference implementation
    FIVEONETWO((uint8_t *)msg, (int)len, ref_out);

    // Call masked implementation
    masked_sha3_512(masked_out, (const uint8_t *)msg, len);

    for (int i = 0; i < 64; ++i) {
        if (ref_out[i] != masked_out[i]) {
            printf("Mismatch SHA3-512 byte[%d]: ref=0x%02X, masked=0x%02X\n",
                   i, ref_out[i], masked_out[i]);
            assert(0);
        }
    }
    printf("PASS: SHA3-512 masked output matches reference\n");
}

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_I2C1_Init();
  MX_I2S3_Init();
  MX_SPI1_Init();
  MX_USB_HOST_Init();
  MX_RNG_Init();
  MX_USART2_UART_Init();


  /* USER CODE BEGIN 2 */
  __HAL_RCC_RNG_CLK_ENABLE();
  HAL_RNG_Init(&hrng);
  setvbuf(stdout, NULL, _IONBF, 0); // Disable buffering completely

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
	  test_masked_vs_reference_step_by_step();
	  test_full_keccak_rounds();
	  test_masked_keccak_round_vs_reference();
	    test_masked_vs_reference_sha3_256();
	    test_masked_vs_reference_sha3_512();
	  /*}
	  const uint8_t input[] = "MaskedKeccakTest";
	     uint8_t unmasked_output[64];
	     uint8_t masked_output[64][MASKING_N];

	     // Call reference unmasked SHA3-512
	     sha3_512(unmasked_output, input, strlen((const char *)input));

	     // Call masked SHA3-512
	     masked_sha3_512(masked_output, input, strlen((const char *)input));

	     // Print results
	     print_hex("SHA3-512 (Unmasked)", unmasked_output, 64);
	     print_masked_hex("SHA3-512 (Masked)", masked_output);
	     */
    /* USER CODE END WHILE */
    MX_USB_HOST_Process();

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}


/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief I2C1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2C1_Init(void)
{

  /* USER CODE BEGIN I2C1_Init 0 */

  /* USER CODE END I2C1_Init 0 */

  /* USER CODE BEGIN I2C1_Init 1 */

  /* USER CODE END I2C1_Init 1 */
  hi2c1.Instance = I2C1;
  hi2c1.Init.ClockSpeed = 100000;
  hi2c1.Init.DutyCycle = I2C_DUTYCYCLE_2;
  hi2c1.Init.OwnAddress1 = 0;
  hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
  hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
  hi2c1.Init.OwnAddress2 = 0;
  hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
  hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
  if (HAL_I2C_Init(&hi2c1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2C1_Init 2 */

  /* USER CODE END I2C1_Init 2 */

}

/**
  * @brief I2S3 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2S3_Init(void)
{

  /* USER CODE BEGIN I2S3_Init 0 */

  /* USER CODE END I2S3_Init 0 */

  /* USER CODE BEGIN I2S3_Init 1 */

  /* USER CODE END I2S3_Init 1 */
  hi2s3.Instance = SPI3;
  hi2s3.Init.Mode = I2S_MODE_MASTER_TX;
  hi2s3.Init.Standard = I2S_STANDARD_PHILIPS;
  hi2s3.Init.DataFormat = I2S_DATAFORMAT_16B;
  hi2s3.Init.MCLKOutput = I2S_MCLKOUTPUT_ENABLE;
  hi2s3.Init.AudioFreq = I2S_AUDIOFREQ_96K;
  hi2s3.Init.CPOL = I2S_CPOL_LOW;
  hi2s3.Init.ClockSource = I2S_CLOCK_PLL;
  hi2s3.Init.FullDuplexMode = I2S_FULLDUPLEXMODE_DISABLE;
  if (HAL_I2S_Init(&hi2s3) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2S3_Init 2 */

  /* USER CODE END I2S3_Init 2 */

}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */

  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */

  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */

  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief SPI1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI1_Init(void)
{

  /* USER CODE BEGIN SPI1_Init 0 */

  /* USER CODE END SPI1_Init 0 */

  /* USER CODE BEGIN SPI1_Init 1 */

  /* USER CODE END SPI1_Init 1 */
  /* SPI1 parameter configuration*/
  hspi1.Instance = SPI1;
  hspi1.Init.Mode = SPI_MODE_MASTER;
  hspi1.Init.Direction = SPI_DIRECTION_2LINES;
  hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi1.Init.NSS = SPI_NSS_SOFT;
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_2;
  hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi1.Init.CRCPolynomial = 10;
  if (HAL_SPI_Init(&hspi1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI1_Init 2 */

  /* USER CODE END SPI1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOE_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(CS_I2C_SPI_GPIO_Port, CS_I2C_SPI_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(OTG_FS_PowerSwitchOn_GPIO_Port, OTG_FS_PowerSwitchOn_Pin, GPIO_PIN_SET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOD, LD4_Pin|LD3_Pin|LD5_Pin|LD6_Pin
                          |Audio_RST_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : CS_I2C_SPI_Pin */
  GPIO_InitStruct.Pin = CS_I2C_SPI_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(CS_I2C_SPI_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : OTG_FS_PowerSwitchOn_Pin */
  GPIO_InitStruct.Pin = OTG_FS_PowerSwitchOn_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(OTG_FS_PowerSwitchOn_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PDM_OUT_Pin */
  GPIO_InitStruct.Pin = PDM_OUT_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF5_SPI2;
  HAL_GPIO_Init(PDM_OUT_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : B1_Pin */
  GPIO_InitStruct.Pin = B1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_EVT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : BOOT1_Pin */
  GPIO_InitStruct.Pin = BOOT1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(BOOT1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : CLK_IN_Pin */
  GPIO_InitStruct.Pin = CLK_IN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF5_SPI2;
  HAL_GPIO_Init(CLK_IN_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : LD4_Pin LD3_Pin LD5_Pin LD6_Pin
                           Audio_RST_Pin */
  GPIO_InitStruct.Pin = LD4_Pin|LD3_Pin|LD5_Pin|LD6_Pin
                          |Audio_RST_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

  /*Configure GPIO pin : OTG_FS_OverCurrent_Pin */
  GPIO_InitStruct.Pin = OTG_FS_OverCurrent_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(OTG_FS_OverCurrent_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : MEMS_INT2_Pin */
  GPIO_InitStruct.Pin = MEMS_INT2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_EVT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(MEMS_INT2_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
