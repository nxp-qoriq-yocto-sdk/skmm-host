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

/*
 * SEC Error Reporting
 *
 */

#include "common.h"

#define JRSTA_SSRC_SHIFT            28
#define JRSTA_CCBERR_CHAID_MASK     0x00f0
#define JRSTA_CCBERR_CHAID_SHIFT    4
#define JRSTA_CCBERR_ERRID_MASK     0x000

#define JRSTA_DECOERR_JUMP          0x08000000
#define JRSTA_DECOERR_INDEX_SHIFT   8
#define JRSTA_DECOERR_INDEX_MASK    0xff00
#define JRSTA_DECOERR_ERROR_MASK    0x00ff

#define SPRINTFCAT(str, format, param, max_alloc)		\
{								\
	char *tmp;						\
	tmp = kzalloc(sizeof(format) + max_alloc, GFP_KERNEL);		\
	sprintf(tmp, format, param);				\
	strcat(str, tmp);					\
	kfree(tmp);						\
}

static inline void report_jump_idx(uint32_t status, char *outstr)
{
	u8 idx = (status & JRSTA_DECOERR_INDEX_MASK) >>
	    JRSTA_DECOERR_INDEX_SHIFT;

	if (status & JRSTA_DECOERR_JUMP)
		strcat(outstr, "jump tgt desc idx ");
	else
		strcat(outstr, "desc idx ");

	SPRINTFCAT(outstr, "%d: ", idx, sizeof("255"));
}

static inline void report_ccb_status(uint32_t status, char *outstr)
{
	char *cha_id_list[] = {
		"",
		"AES",
		"DES, 3DES",
		"ARC4",
		"MD5, SHA-1, SH-224, SHA-256, SHA-384, SHA-512",
		"RNG",
		"SNOW f8",
		"Kasumi f8, f9",
		"All Public Key Algorithms",
		"CRC",
		"SNOW f9",
	};
	char *err_id_list[] = {
		"None. No error.",
		"Mode error.",
		"Data size error.",
		"Key size error.",
		"PKHA A memory size error.",
		"PKHA B memory size error.",
		"Data arrived out of sequence error.",
		"PKHA divide-by-zero error.",
		"PKHA modulus even error.",
		"DES key parity error.",
		"ICV check failed.",
		"Hardware error.",
		"Unsupported CCM AAD size.",
		"Class 1 CHA is not reset",
		"Invalid CHA combination was selected",
		"Invalid CHA selected.",
	};
	u8 cha_id = (status & JRSTA_CCBERR_CHAID_MASK) >>
	    JRSTA_CCBERR_CHAID_SHIFT;
	u8 err_id = status & JRSTA_CCBERR_ERRID_MASK;

	report_jump_idx(status, outstr);

	if (cha_id < ARRAY_SIZE(cha_id_list)) {
		SPRINTFCAT(outstr, "%s: ", cha_id_list[cha_id],
			   strlen(cha_id_list[cha_id]));
	} else {
		SPRINTFCAT(outstr, "unidentified cha_id value 0x%02x: ",
			   cha_id, sizeof("ff"));
	}

	if (err_id < ARRAY_SIZE(err_id_list)) {
		SPRINTFCAT(outstr, "%s", err_id_list[err_id],
			   strlen(err_id_list[err_id]));
	} else {
		SPRINTFCAT(outstr, "unidentified err_id value 0x%02x",
			   err_id, sizeof("ff"));
	}
}

static inline void report_jump_status(uint32_t status, char *outstr)
{
	SPRINTFCAT(outstr, "%s() not implemented", __func__, sizeof(__func__));
}

static inline void report_deco_status(uint32_t status, char *outstr)
{
	const struct {
		u8 value;
		char *error_text;
	} desc_error_list[] = {
		{
		0x00, "None. No error."}, {
		0x01,
			    "SGT Length Error. The descriptor is trying to read "
			    "more data than is contained in the SGT table."}, {
		0x02, "Reserved."}, {
		0x03,
			    "Job Ring Control Error. There is a bad value in the "
			    "Job Ring Control register."}, {
		0x04,
			    "Invalid Descriptor Command. The Descriptor Command "
			    "field is invalid."}, {
		0x05, "Reserved."}, {
		0x06, "Invalid KEY Command"}, {
		0x07, "Invalid LOAD Command"}, {
		0x08, "Invalid STORE Command"}, {
		0x09, "Invalid OPERATION Command"}, {
		0x0A, "Invalid FIFO LOAD Command"}, {
		0x0B, "Invalid FIFO STORE Command"}, {
		0x0C, "Invalid MOVE Command"}, {
		0x0D,
			    "Invalid JUMP Command. A nonlocal JUMP Command is "
			    "invalid because the target is not a Job Header "
			    "Command, or the jump is from a Trusted Descriptor to "
			    "a Job Descriptor, or because the target Descriptor "
			    "contains a Shared Descriptor."}, {
		0x0E, "Invalid MATH Command"}, {
		0x0F, "Invalid SIGNATURE Command"}, {
		0x10,
			    "Invalid Sequence Command. A SEQ IN PTR OR SEQ OUT PTR "
			    "Command is invalid or a SEQ KEY, SEQ LOAD, SEQ FIFO "
			    "LOAD, or SEQ FIFO STORE decremented the input or "
			    "output sequence length below 0. This error may result "
			    "if a built-in PROTOCOL Command has encountered a "
			    "malformed PDU."}, {
		0x11, "Skip data type invalid. The type must be 0xE or 0xF."},
		{
		0x12, "Shared Descriptor Header Error"}, {
		0x13,
			    "Header Error. Invalid length or parity, or certain "
			    "other problems."}, {
		0x14,
			    "Burster Error. Burster has gotten to an illegal "
			    "state"}, {
		0x15,
			    "Context Register Length Error. The descriptor is "
			    "trying to read or write past the end of the Context "
			    "Register. A SEQ LOAD or SEQ STORE with the VLF bit "
			    "set was executed with too large a length in the "
			    "variable length register (VSOL for SEQ STORE or VSIL "
			    "for SEQ LOAD)."}, {
		0x16, "DMA Error"}, {
		0x17, "Reserved."}, {
		0x1A, "Job failed due to JR reset"}, {
		0x1B, "Job failed due to Fail Mode"}, {
		0x1C, "DECO Watchdog timer timeout error"}, {
		0x1D,
			    "DECO tried to copy a key from another DECO but the "
			    "other DECO's Key Registers were locked"}, {
		0x1E,
			    "DECO attempted to copy data from a DECO that had an "
			    "unmasked Descriptor error"}, {
		0x1F,
			    "LIODN error. DECO was trying to share from itself or "
			    "from another DECO but the two Non-SEQ LIODN values "
			    "didn't match or the 'shared from' DECO's Descriptor "
			    "required that the SEQ LIODNs be the same and they "
			    "aren't."}, {
		0x20,
			    "DECO has completed a reset initiated via the DRR "
			    "register"}, {
		0x21,
			    "Nonce error. When using EKT (CCM) key encryption "
			    "option in the FIFO STORE Command, the Nonce counter "
			    "reached its maximum value and this encryption mode "
			    "can no longer be used."}, {
		0x22,
			    "Meta data is too large (> 511 bytes) for TLS decap "
			    "(input frame; block ciphers) and IPsec decap (output "
			    "frame, when doing the next header byte update) and "
			    "DCRC (output frame)."}, {
		0x80, "DNR (do not run) error"}, {
		0x81, "undefined protocol command"}, {
		0x82, "invalid setting in PDB"}, {
		0x83, "Anti-replay LATE error"}, {
		0x84, "Anti-replay REPLAY error"}, {
		0x85, "Sequence number overflow"}, {
		0x86, "Sigver invalid signature"}, {
		0x87, "DSA Sign Illegal test descriptor"}, {
		0x88,
			    "Protocol Format Error - A protocol has seen an error "
			    "in the format of data received. When running RSA, "
			    "this means that formatting with random padding was "
			    "used, and did not follow the form: 0x00, 0x02, 8-to-N "
			    "bytes of non-zero pad, 0x00, F data."}, {
		0x89,
			    "Protocol Size Error - A protocol has seen an error in "
			    "size. When running RSA, pdb size N < (size of F) when "
			    "no formatting is used; or pdb size N < (F + 11) when "
			    "formatting is used."}, {
		0xC1, "Blob Command error: Undefined mode"}, {
		0xC2, "Blob Command error: Secure Memory Blob mode error"},
		{
		0xC4,
			    "Blob Command error: Black Blob key or input size "
			    "error"}, {
		0xC5, "Blob Command error: Invalid key destination"}, {
		0xC8, "Blob Command error: Trusted/Secure mode error"}, {
		0xF0,
			    "IPsec TTL or hop limit field either came in as 0, "
			    "or was decremented to 0"}, {
	0xF1, "3GPP HFN matches or exceeds the Threshold"},};
	u8 desc_error = status & JRSTA_DECOERR_ERROR_MASK;
	int i;

	report_jump_idx(status, outstr);

	for (i = 0; i < ARRAY_SIZE(desc_error_list); i++)
		if (desc_error_list[i].value == desc_error)
			break;

	if (i != ARRAY_SIZE(desc_error_list) && desc_error_list[i].error_text) {
		SPRINTFCAT(outstr, "%s", desc_error_list[i].error_text,
			   strlen(desc_error_list[i].error_text));
	} else {
		SPRINTFCAT(outstr, "unidentified error value 0x%02x",
			   desc_error, sizeof("ff"));
	}
}

static inline void report_jr_status(uint32_t status, char *outstr)
{
}

static inline void report_cond_code_status(uint32_t status, char *outstr)
{
	SPRINTFCAT(outstr, "%s() not implemented", __func__, sizeof(__func__));
}

static inline int sec_jr_strstatus(char *outstr, uint32_t status)
{
	int ret = 0;
	struct stat_src {
		void (*report_ssed) (uint32_t status, char *outstr);
		char *error;
	} status_src[] = {
		{
		NULL, "No error"}, {
		NULL, NULL}, {
		report_ccb_status, "CCB"}, {
		report_jump_status, "Jump"}, {
		report_deco_status, "DECO"}, {
		NULL, NULL}, {
		report_jr_status, "Job Ring"}, {
	report_cond_code_status, "Condition Code"},};
	uint32_t ssrc = status >> JRSTA_SSRC_SHIFT;

	sprintf(outstr, "%s: ", status_src[ssrc].error);

	if (status_src[ssrc].report_ssed) {
		status_src[ssrc].report_ssed(status, outstr);
		ret = -1;
	} else
		ret = 0;

	return ret;
}
