/* Copyright 2026 Quantova Inc */
/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QCARDANO_PQC_H
#define QCARDANO_PQC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t qc_verify_ml_dsa_65(const uint8_t *pk, size_t pk_len,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len);

int32_t qc_verify_ml_dsa_87(const uint8_t *pk, size_t pk_len,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len);

int32_t qc_verify_slh_dsa(const uint8_t *pk, size_t pk_len,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif
