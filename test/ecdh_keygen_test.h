/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of Freescale Semiconductor nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE)ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* *************** For P-256 Buffers *************** */

static uint8_t Q_256[] = {
      0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,    /* p */
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF
};

static int32_t q_256_len = sizeof(Q_256);

static uint8_t AB_256[] = {
      0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,    /* a */
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFC,
      0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7,0xB3,0xEB,    /* b */
      0xBD,0x55,0x76,0x98,0x86,0xBC,0x65,0x1D,0x06,0xB0,
      0xCC,0x53,0xB0,0xF6,0x3B,0xCE,0x3C,0x3E,0x27,0xD2,
      0x60,0x4B
};

static int32_t ab_256_len = sizeof(AB_256);

static uint8_t G_256[] = { 
      0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,    /* x */
      0xE6,0xE5,0x63,0xA4,0x40,0xF2,0x77,0x03,0x7D,0x81,
      0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,
      0xC2,0x96,
      0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,    /* y */
      0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,
      0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,
      0x51,0xf5
};

static int32_t g_256_len = sizeof(G_256);

static uint8_t R_256[] = {
      0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,    /* order */
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,
      0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,
      0x25,0x51
};

static int32_t r_256_len = sizeof(R_256);


/* *************** For P-384 Buffers *************** */

static uint8_t Q_384[] = {
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    /* p */
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF
};

static int32_t q_384_len = sizeof(Q_384);

static uint8_t AB_384[] = {
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    /* a */
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFC,
      0xB3,0x31,0x2F,0xA7,0xE2,0x3E,0xE7,0xE4,0x98,0x8E,    /* b */
      0x05,0x6B,0xE3,0xF8,0x2D,0x19,0x18,0x1D,0x9C,0x6E,
      0xFE,0x81,0x41,0x12,0x03,0x14,0x08,0x8F,0x50,0x13,
      0x87,0x5A,0xC6,0x56,0x39,0x8D,0x8A,0x2E,0xD1,0x9D,
      0x2A,0x85,0xC8,0xED,0xD3,0xEC,0x2A,0xEF
};

static int32_t ab_384_len = sizeof(AB_384);

static uint8_t G_384[] = {
      0xAA,0x87,0xCA,0x22,0xBE,0x8B,0x05,0x37,0x8E,0xB1,    /* x */
      0xC7,0x1E,0xF3,0x20,0xAD,0x74,0x6E,0x1D,0x3B,0x62,
      0x8B,0xA7,0x9B,0x98,0x59,0xF7,0x41,0xE0,0x82,0x54,
      0x2A,0x38,0x55,0x02,0xF2,0x5D,0xBF,0x55,0x29,0x6C,
      0x3A,0x54,0x5E,0x38,0x72,0x76,0x0A,0xB7,
      0x36,0x17,0xde,0x4a,0x96,0x26,0x2c,0x6f,0x5d,0x9e,    /* y */
      0x98,0xbf,0x92,0x92,0xdc,0x29,0xf8,0xf4,0x1d,0xbd,
      0x28,0x9a,0x14,0x7c,0xe9,0xda,0x31,0x13,0xb5,0xf0,
      0xb8,0xc0,0x0a,0x60,0xb1,0xce,0x1d,0x7e,0x81,0x9d,
      0x7a,0x43,0x1d,0x7c,0x90,0xea,0x0e,0x5f
};

static int32_t g_384_len = sizeof(G_384);

static uint8_t R_384[] = {
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    /* order */
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xC7,0x63,0x4D,0x81,0xF4,0x37,
      0x2D,0xDF,0x58,0x1A,0x0D,0xB2,0x48,0xB0,0xA7,0x7A,
      0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73
};

static int32_t r_384_len = sizeof(R_384);

/* *************** For P-521 Buffers *************** */
static int8_t Q_521[] = {
      0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    /* p */
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

static int32_t q_521_len = sizeof(Q_521);

static int8_t AB_521[] = {
      0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    /* a */
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
      0x00,0x51,0x95,0x3E,0xB9,0x61,0x8E,0x1C,0x9A,0x1F,    /* b */
      0x92,0x9A,0x21,0xA0,0xB6,0x85,0x40,0xEE,0xA2,0xDA,
      0x72,0x5B,0x99,0xB3,0x15,0xF3,0xB8,0xB4,0x89,0x91,
      0x8E,0xF1,0x09,0xE1,0x56,0x19,0x39,0x51,0xEC,0x7E,
      0x93,0x7B,0x16,0x52,0xC0,0xBD,0x3B,0xB1,0xBF,0x07,
      0x35,0x73,0xDF,0x88,0x3D,0x2C,0x34,0xF1,0xEF,0x45,
      0x1F,0xD4,0x6B,0x50,0x3F,0x00
};

static int32_t ab_521_len = sizeof(AB_521);

static int8_t G_521[] = {
      0x00,0xC6,0x85,0x8E,0x06,0xB7,0x04,0x04,0xE9,0xCD,    /* x */
      0x9E,0x3E,0xCB,0x66,0x23,0x95,0xB4,0x42,0x9C,0x64,
      0x81,0x39,0x05,0x3F,0xB5,0x21,0xF8,0x28,0xAF,0x60,
      0x6B,0x4D,0x3D,0xBA,0xA1,0x4B,0x5E,0x77,0xEF,0xE7,
      0x59,0x28,0xFE,0x1D,0xC1,0x27,0xA2,0xFF,0xA8,0xDE,
      0x33,0x48,0xB3,0xC1,0x85,0x6A,0x42,0x9B,0xF9,0x7E,
      0x7E,0x31,0xC2,0xE5,0xBD,0x66,
      0x01,0x18,0x39,0x29,0x6a,0x78,0x9a,0x3b,0xc0,0x04,    /* y */
      0x5c,0x8a,0x5f,0xb4,0x2c,0x7d,0x1b,0xd9,0x98,0xf5,
      0x44,0x49,0x57,0x9b,0x44,0x68,0x17,0xaf,0xbd,0x17,
      0x27,0x3e,0x66,0x2c,0x97,0xee,0x72,0x99,0x5e,0xf4,
      0x26,0x40,0xc5,0x50,0xb9,0x01,0x3f,0xad,0x07,0x61,
      0x35,0x3c,0x70,0x86,0xa2,0x72,0xc2,0x40,0x88,0xbe,
      0x94,0x76,0x9f,0xd1,0x66,0x50
};

static int32_t g_521_len = sizeof(G_521);

static int8_t R_521[] = {
      0x01,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    /* order */
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFA,0x51,0x86,0x87,0x83,0xBF,0x2F,
      0x96,0x6B,0x7F,0xCC,0x01,0x48,0xF7,0x09,0xA5,0xD0,
      0x3B,0xB5,0xC9,0xB8,0x89,0x9C,0x47,0xAE,0xBB,0x6F,
      0xB7,0x1E,0x91,0x38,0x64,0x09
};

static int32_t r_521_len = sizeof(R_521);


/* *************** For B-283 Buffers *************** */

static uint8_t Q_283[] = {
      0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x10,0xA1
};

static int32_t q_283_len = sizeof(Q_283);

static uint8_t AB_283[] = {
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x01,
      0x03, 0xD8, 0xC9, 0x3D, 0x3B, 0x0E, 0xA8, 0x1D,
      0x92, 0x94, 0x03, 0x4D, 0x7E, 0xE3, 0x13, 0x5D, 0x0A, 0xC5,
      0xFC, 0x8D, 0x9C, 0xB0, 0x27, 0x6F, 0x72, 0x11, 0xF8, 0x80,
      0xF0, 0xD8, 0x1C, 0xA4, 0xC6, 0xE8, 0x7B, 0x38
};

static int32_t ab_283_len = sizeof(AB_283);

static uint8_t G_283[] = { 
      0x05,0xF9,0x39,0x25,0x8D,0xB7,0xDD,0x90,0xE1,0x93,    
      0x4F,0x8C,0x70,0xB0,0xDF,0xEC,0x2E,0xED,0x25,0xB8,
      0x55,0x7E,0xAC,0x9C,0x80,0xE2,0xE1,0x98,0xF8,0xCD,
      0xBE,0xCD,0x86,0xB1,0x20,0x53,
      0x03,0x67,0x68,0x54,0xFE,0x24,0x14,0x1C,0xB9,0x8F,    
      0xE6,0xD4,0xB2,0x0D,0x02,0xB4,0x51,0x6F,0xF7,0x02,
      0x35,0x0E,0xDD,0xB0,0x82,0x67,0x79,0xC8,0x13,0xF0,
      0xDF,0x45,0xBE,0x81,0x12,0xF4
};

static int32_t g_283_len = sizeof(G_283);

static uint8_t R_283[] = {
      0x03,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xEF,0x90,
      0x39,0x96,0x60,0xFC,0x93,0x8A,0x90,0x16,0x5B,0x04,
      0x2A,0x7C,0xEF,0xAD,0xB3,0x07
};

static int32_t r_283_len = sizeof(R_283);


/* *************** For B-409 Buffers *************** */
static uint8_t Q_409[] = {
      0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x01
};

static int32_t q_409_len = sizeof(Q_409);

static uint8_t AB_409[] = {
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x01,
	  0x01, 0x49, 0xB8, 0xB7, 0xBE, 0xBD, 0x9B, 0x63,
      0x65, 0x3E, 0xF1, 0xCD, 0x8C, 0x6A, 0x5D, 0xD1, 0x05, 0xA2,
      0xAA, 0xAC, 0x36, 0xFE, 0x2E, 0xAE, 0x43, 0xCF, 0x28, 0xCE,
      0x1C, 0xB7, 0xC8, 0x30, 0xC1, 0xEC, 0xDB, 0xFA, 0x41, 0x3A,
      0xB0, 0x7F, 0xE3, 0x5A, 0x57, 0x81, 0x1A, 0xE4, 0xF8, 0x8D,
      0x30, 0xAC, 0x63, 0xFB
};

static int32_t ab_409_len = sizeof(AB_409);

static uint8_t G_409[] = {
	  0x01,0x5D,0x48,0x60,0xD0,0x88,0xDD,0xB3,0x49,0x6B,   
      0x0C,0x60,0x64,0x75,0x62,0x60,0x44,0x1C,0xDE,0x4A,
      0xF1,0x77,0x1D,0x4D,0xB0,0x1F,0xFE,0x5B,0x34,0xE5,
      0x97,0x03,0xDC,0x25,0x5A,0x86,0x8A,0x11,0x80,0x51,
      0x56,0x03,0xAE,0xAB,0x60,0x79,0x4E,0x54,0xBB,0x79,
      0x96,0xA7,
      0x00,0x61,0xB1,0xCF,0xAB,0x6B,0xE5,0xF3,0x2B,0xBF,    
      0xA7,0x83,0x24,0xED,0x10,0x6A,0x76,0x36,0xB9,0xC5,
      0xA7,0xBD,0x19,0x8D,0x01,0x58,0xAA,0x4F,0x54,0x88,
      0xD0,0x8F,0x38,0x51,0x4F,0x1F,0xDF,0x4B,0x4F,0x40,
      0xD2,0x18,0x1B,0x36,0x81,0xC3,0x64,0xBA,0x02,0x73,
      0xC7,0x06
};

static int32_t g_409_len = sizeof(G_409);

static uint8_t R_409[] = {
      0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xE2,0xAA,0xD6,
      0xA6,0x12,0xF3,0x33,0x07,0xBE,0x5F,0xA4,0x7C,0x3C,
      0x9E,0x05,0x2F,0x83,0x81,0x64,0xCD,0x37,0xD9,0xA2,
      0x11,0x73
};

static int32_t r_409_len = sizeof(R_409);


/* *************** For B-571 Buffers *************** */

static int8_t Q_571[] = {
      0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0x04,0x25
};

static int32_t q_571_len = sizeof(Q_571);

static int8_t AB_571[] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,    
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x01,
    0x06, 0x39, 0x5D, 0xB2, 0x2A, 0xB5, 0x94, 0xB1,
    0x86, 0x8C, 0xED, 0x95, 0x25, 0x78, 0xB6, 0x53, 0x9F, 0xAB,
    0xA6, 0x94, 0x06, 0xD9, 0xB2, 0x98, 0x61, 0x23, 0xA1, 0x85,
    0xC8, 0x58, 0x32, 0xE2, 0x5F, 0xD5, 0xB6, 0x38, 0x33, 0xD5,
    0x14, 0x42, 0xAB, 0xF1, 0xA9, 0xC0, 0x5F, 0xF0, 0xEC, 0xBD,
    0x88, 0xD7, 0xF7, 0x79, 0x97, 0xF4, 0xDC, 0x91, 0x56, 0xAA,
    0xF1, 0xCE, 0x08, 0x16, 0x46, 0x86, 0xDD, 0xFF, 0x75, 0x11,
    0x6F, 0xBC, 0x9A, 0x7A
};

static int32_t ab_571_len = sizeof(AB_571);

static int8_t G_571[] = {
      0x03,0x03,0x00,0x1D,0x34,0xB8,0x56,0x29,0x6C,0x16,    
      0xC0,0xD4,0x0D,0x3C,0xD7,0x75,0x0A,0x93,0xD1,0xD2,
      0x95,0x5F,0xA8,0x0A,0xA5,0xF4,0x0F,0xC8,0xDB,0x7B,
      0x2A,0xBD,0xBD,0xE5,0x39,0x50,0xF4,0xC0,0xD2,0x93,
      0xCD,0xD7,0x11,0xA3,0x5B,0x67,0xFB,0x14,0x99,0xAE,
      0x60,0x03,0x86,0x14,0xF1,0x39,0x4A,0xBF,0xA3,0xB4,
      0xC8,0x50,0xD9,0x27,0xE1,0xE7,0x76,0x9C,0x8E,0xEC,
      0x2D,0x19,
      0x03,0x7B,0xF2,0x73,0x42,0xDA,0x63,0x9B,0x6D,0xCC,    
      0xFF,0xFE,0xB7,0x3D,0x69,0xD7,0x8C,0x6C,0x27,0xA6,
      0x00,0x9C,0xBB,0xCA,0x19,0x80,0xF8,0x53,0x39,0x21,
      0xE8,0xA6,0x84,0x42,0x3E,0x43,0xBA,0xB0,0x8A,0x57,
      0x62,0x91,0xAF,0x8F,0x46,0x1B,0xB2,0xA8,0xB3,0x53,
      0x1D,0x2F,0x04,0x85,0xC1,0x9B,0x16,0xE2,0xF1,0x51,
      0x6E,0x23,0xDD,0x3C,0x1A,0x48,0x27,0xAF,0x1B,0x8A,
      0xC1,0x5B
};

static int32_t g_571_len = sizeof(G_571);

static int8_t R_571[] = {
      0x03,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,    
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xE6,0x61,0xCE,0x18,
      0xFF,0x55,0x98,0x73,0x08,0x05,0x9B,0x18,0x68,0x23,
      0x85,0x1E,0xC7,0xDD,0x9C,0xA1,0x16,0x1D,0xE9,0x3D,
      0x51,0x74,0xD6,0x6E,0x83,0x82,0xE9,0xBB,0x2F,0xE8,
      0x4E,0x47
};

static int32_t r_571_len = sizeof(R_571);

