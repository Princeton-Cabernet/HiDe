#pragma once

// // ternary match rules for sign bit
// // Width of these values is 32 bits
#define TERNARY_NEGATIVE 32w0x80000000 &&& 32w0x80000000
#define TERNARY_POSITIVE 32w0 &&& 32w0x80000000
#define TERNARY_ZERO 32w0 &&& 32w0xffffffff
// #define TERNARY_DONT_CARE 32w0 &&& 32w0
// //alias
// #define TERNARY_NONNEG_CHECK TERNARY_POS_CHECK

// Default values
#define NULL 0

#define CRC_POLY_0 0x8005
#define CRC_POLY_1 0x0589
#define CRC_POLY_2 0x3D65
#define CRC_POLY_3 0x1021

#define HONEYPOT_SIGNATURE_SEED 4w3

// Mirroring: Must be installed by the control plane for it to work
const MirrorType_t MIRROR_TYPE_I2E = 0x1;
const MirrorType_t MIRROR_TYPE_E2E = 0x2;
