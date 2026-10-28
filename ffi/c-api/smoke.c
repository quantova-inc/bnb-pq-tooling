/* Copyright 2026 Quantova Inc */
/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "qcardano_pqc.h"

int main(void) {
    uint8_t buf[8] = {0};

    assert(qc_verify_ml_dsa_65(0, 0, 0, 0, 0, 0) == 0);
    assert(qc_verify_ml_dsa_87(0, 0, 0, 0, 0, 0) == 0);
    assert(qc_verify_slh_dsa(0, 0, 0, 0, 0, 0) == 0);

    assert(qc_verify_ml_dsa_87(buf, sizeof buf, buf, sizeof buf, buf, sizeof buf) == 0);

    printf("c abi link ok malformed inputs rejected\n");
    return 0;
}
