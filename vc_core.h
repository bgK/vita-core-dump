/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef VC_CORE_H
#define VC_CORE_H

#include <inttypes.h>

typedef struct VcCore VcCore;

typedef enum VcStopReason {
	VcStopReasonUndefinedInstructionException = 0x30002,
	VcStopReasonPrefetchAbortException        = 0x30003,
	VcStopReasonDataAbortException            = 0x30004,
	VcStopReasonDivisionByEero                = 0x60080,
} VcStopReason;

typedef struct VcModule {
	char name[32];
	uint32_t load_address;
	uint32_t size;
} VcModule;

typedef struct VcThread {
	char name[32];
	uint16_t status;
	uint32_t stop_reason;
	uint32_t registers[16];

	uint32_t ifsr;
	uint32_t ifar;
	uint32_t dfsr;
	uint32_t dfar;
} VcThread;

VcCore *vc_core_new();
int vc_core_load(VcCore *core, const char *filename);
void vc_core_free(VcCore *core);

int vc_core_get_thread_count(VcCore *core, uint32_t *out_count);
int vc_core_get_thread(VcCore *core, uint32_t index, VcThread *out_thread);

const char *vc_core_get_thread_status_name(uint32_t thread_status);
const char *vc_core_get_thread_stop_reason_name(uint32_t stop_reason);

int vc_core_get_module_count(VcCore *core, uint32_t *out_count);
int vc_core_get_module(VcCore *core, uint32_t module_index, VcModule *out_module);

int vc_core_memory_read(VcCore *core, uint32_t address, uint32_t length, uint8_t **out_buffer, uint32_t *out_bytes_read);
int vc_core_memory_read_u32(VcCore *core, uint32_t address, uint32_t *out_result);

int vc_core_get_error_code(VcCore *core);
const char *vc_core_get_error_message(VcCore *core);

#define VC_CORE_ERROR_ALREADY_LOADED    1
#define VC_CORE_ERROR_NOT_LOADED        2
#define VC_CORE_ERROR_CORE_OPEN_FAILED  3
#define VC_CORE_ERROR_INVALID_CORE_DUMP 4
#define VC_CORE_ERROR_NOT_FOUND         5

#endif // VC_CORE_H
