/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef VC_ELF_H
#define VC_ELF_H

#include <inttypes.h>

#define ARM_REG_SP 13
#define ARM_REG_LR 14
#define ARM_REG_PC 15

#define ARM_REG_COUNT 16

typedef struct VcElf VcElf;

typedef struct VcAddressInfo {
	const char *line_filename;
	int line_number;
	const char *function_name;
	int function_offset;
} VcAddressInfo;

typedef struct VcFrameState {
	uint32_t registers[ARM_REG_COUNT];
} VcFrameState;

typedef struct VcUnwindCallbacks {
	void *user_data;

	int (*memory_read)(void *user_data, uint32_t address, uint32_t *out_result);
} VcUnwindCallbacks;

VcElf *vc_elf_new();
int vc_elf_load(VcElf *elf, const char *filename);
void vc_elf_free(VcElf *elf);

int vc_elf_get_base_address(VcElf *elf, uint32_t *out_address);
int vc_elf_get_memory_size(VcElf *elf, uint32_t *out_size);
int vc_elf_get_pc_info(VcElf *elf, uint32_t address, VcAddressInfo *out_pc_info);
int vc_elf_unwind_one_frame(VcElf *elf, VcUnwindCallbacks *callbacks, VcFrameState *frame_state, VcFrameState *out_caller_frame_state);

int vc_elf_get_error_code(VcElf *elf);
const char *vc_elf_get_error_message(VcElf *elf);

#define VC_ELF_ERROR_ALREADY_LOADED    1
#define VC_ELF_ERROR_NOT_LOADED        2
#define VC_ELF_ERROR_OPEN_FAILED       3
#define VC_ELF_ERROR_INVALID_ELF       4
#define VC_ELF_ERROR_NOT_FOUND         5
#define VC_ELF_ERROR_NOT_IMPLEMENTED   6

#endif // VC_ELF_H
