/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "vc_address_space.h"

#include "vc_core.h"
#include "vc_elf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERROR_MESSAGE_SIZE 2048

#define FREE(x) \
	free(x);    \
	x = NULL;

typedef struct VcAddressSpace {
	uint32_t module_count;
	VcAddressSpaceModule *modules;

	int error_code;
	char error_message[ERROR_MESSAGE_SIZE];
} VcAddressSpace;

VcAddressSpace *vc_address_space_new() {
	VcAddressSpace *address_space = calloc(1, sizeof(VcAddressSpace));
	if (!address_space) {
		return NULL;
	}

	return address_space;
}

void vc_address_space_free(VcAddressSpace *address_space) {
	if (!address_space) {
		return;
	}

	for (uint32_t i = 0; i < address_space->module_count; i++) {
		VcAddressSpaceModule *module = &address_space->modules[i];
		FREE(module->name);
		vc_elf_free(module->elf);
	}

	FREE(address_space->modules);
	FREE(address_space);
}

int vc_address_space_get_error_code(VcAddressSpace *address_space) {
	return address_space->error_code;
}

const char *vc_address_space_get_error_message(VcAddressSpace *address_space) {
	return address_space->error_message;
}

static void vc_address_space_set_error(VcAddressSpace *address_space, int code, const char *message, ...) {
	va_list args;
	va_start(args, message);

	address_space->error_code = code;

	vsnprintf(address_space->error_message, ERROR_MESSAGE_SIZE, message, args);

	va_end(args);
}

VcAddressSpaceModule *vc_address_space_add_module(VcAddressSpace *address_space, const char *name, uint32_t load_address, uint32_t size) {
	VcAddressSpaceModule *new_module;
	if (!address_space->modules) {
		address_space->module_count = 1;
		address_space->modules = malloc(sizeof(VcAddressSpaceModule));
		new_module = address_space->modules;
	} else {
		address_space->module_count++;
		address_space->modules = realloc(address_space->modules, sizeof(VcAddressSpaceModule) * address_space->module_count);
		new_module = &address_space->modules[address_space->module_count - 1];
	}

	memset(new_module, 0, sizeof(VcAddressSpaceModule));
	new_module->name         = strdup(name);
	new_module->load_address = load_address;
	new_module->size         = size;

	return new_module;
}

int vc_address_space_add_modules_from_core(VcAddressSpace *address_space, VcCore *core) {
	uint32_t core_module_count;
	if (vc_core_get_module_count(core, &core_module_count) < 0) {
		vc_address_space_set_error(address_space, VC_ADDRESS_SPACE_ERROR_INVALID_CORE, "Failed to get core module count: %s", vc_core_get_error_message(core));
		return -1;
	}

	for (uint32_t core_module_index = 0; core_module_index < core_module_count; core_module_index++) {
		VcModule core_module;
		if (vc_core_get_module(core, core_module_index, &core_module) < 0) {
			vc_address_space_set_error(address_space, VC_ADDRESS_SPACE_ERROR_INVALID_CORE, "Failed to get core module %d: %s", core_module_index, vc_core_get_error_message(core));
			return -1;
		}

		vc_address_space_add_module(address_space, core_module.name, core_module.load_address, core_module.size);
	}

	return 0;
}

int vc_address_space_find_module_by_address(VcAddressSpace *address_space, uint32_t address, VcAddressSpaceModule **out_module) {
	for (uint32_t module_index = 0; module_index < address_space->module_count; module_index++) {
		VcAddressSpaceModule *module = &address_space->modules[module_index];
		if (address >= module->load_address && address < (module->load_address + module->size)) {
			*out_module = module;
			return 0;
		}
	}

	return -1;
}

int vc_address_space_find_module_by_name(VcAddressSpace *address_space, const char *name, VcAddressSpaceModule **out_module) {
	for (uint32_t module_index = 0; module_index < address_space->module_count; module_index++) {
		VcAddressSpaceModule *module = &address_space->modules[module_index];
		if (strcasecmp(name, module->name) == 0) {
			*out_module = module;
			return 0;
		}
	}

	return -1;
}
