/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef VC_ADDRESS_SPACE_H
#define VC_ADDRESS_SPACE_H

#include <inttypes.h>

typedef struct VcAddressSpace VcAddressSpace;
typedef struct VcCore VcCore;
typedef struct VcElf VcElf;

typedef struct VcAddressSpaceModule {
	char *name;
	uint32_t load_address;
	uint32_t size;
	VcElf *elf;
} VcAddressSpaceModule;

VcAddressSpace *vc_address_space_new();
void vc_address_space_free(VcAddressSpace *address_space);

int vc_address_space_get_error_code(VcAddressSpace *address_space);
const char *vc_address_space_get_error_message(VcAddressSpace *address_space);

VcAddressSpaceModule *vc_address_space_add_module(VcAddressSpace *address_space, const char *name, uint32_t load_address, uint32_t size);
int vc_address_space_add_modules_from_core(VcAddressSpace *address_space, VcCore *core);

int vc_address_space_find_module_by_address(VcAddressSpace *address_space, uint32_t address, VcAddressSpaceModule **out_module);
int vc_address_space_find_module_by_name(VcAddressSpace *address_space, const char *name, VcAddressSpaceModule **out_module);

#define VC_ADDRESS_SPACE_ERROR_INVALID_CORE    1

#endif // VC_ADDRESS_SPACE_H
