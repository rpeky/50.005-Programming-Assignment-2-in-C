#pragma once
#include "sftp.h"

/* Zero-extend 1024-bit server key into 2048-bit bn_t. */
static const rsa_pub S_PUB = {
    .n =
        {
            /* top 1024 bits: zeros */
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            /* bottom 1024 bits: your 32 words (MSW first) */
            /* 0xXXXXXXXX, ... 32 entries ... */
        },
    .e = 65537u};

static const rsa_priv S_PRIV = {
    .n =
        {
            /* identical to S_PUB.n */
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            /* bottom 32 words of modulus */
            /* 0xXXXXXXXX, ... */
        },
    .d = {
        /* top 1024 bits zero */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* bottom 32 words = privateExponent */
        /* 0xXXXXXXXX, ... */
    }};
