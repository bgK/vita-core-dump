/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "vc_elf.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dwarf.h>
#include <elfutils/libdw.h>

#define FREE(x) \
	free(x);    \
	x = NULL;

#define DWARF_EXPRESSION_MAX_STACK 0x100

typedef struct VcElf {
	bool loaded;
	char *filename;

	int elf_fd;
	Elf *elf;

	Elf_Data *symbols_data;
	size_t symbols_string_table_index;
	uint32_t symbols_count;

	Elf_Data *exidx_data;
	uint32_t exidx_start_address;
	Elf_Data *extab_data;
	uint32_t extab_start_address;

	Dwarf *dwarf;
	Dwarf_CFI *dwarf_cfi;
	bool dwarf_cfi_from_elf;

	uint32_t base_address;
	uint32_t memory_size;

	char *module_name;

	int error_code;
	char error_message[VC_ELF_ERROR_MESSAGE_SIZE];
} VcElf;

typedef struct DwarfExpressionState {
	uint64_t stack[DWARF_EXPRESSION_MAX_STACK];
	uint32_t stack_position;
} DwarfExpressionState;

typedef struct DwarfTypeInfo {
	int tag;
	Dwarf_Word size;
	Dwarf_Word encoding;
} DwarfTypeInfo;

typedef struct ExIdxEntry {
	uint32_t address_offset;
	uint32_t instruction;
} ExIdxEntry;

typedef struct ExTabScript {
	uint32_t *instructions;
	int current_byte;
	int remaining_bytes;
} ExTabScript;

typedef enum DwarfExpressionResultType {
	DwarfExpressionResultTypeAddress,
	DwarfExpressionResultTypeValue,
	DwarfExpressionResultTypeRegister
} DwarfExpressionResultType;

typedef struct SceModuleInfo {
	uint16_t attributes;
	uint16_t version;
	char     name[27];
	uint8_t  type;
	uint32_t gp_value;
	uint32_t export_top;
	uint32_t export_end;
	uint32_t import_top;
	uint32_t import_end;
	uint32_t module_nid;
	uint32_t tls_start;
	uint32_t tls_filesz;
	uint32_t tls_memsz;
	uint32_t module_start;
	uint32_t module_stop;
	uint32_t exidx_top;
	uint32_t exidx_end;
	uint32_t extab_top;
	uint32_t extab_end;
} SceModuleInfo;

#define ET_SCE_EXEC         0xfe00
#define ET_SCE_RELEXEC      0xfe04

static void vc_elf_set_error(VcElf *elf, int code, const char *message, ...) __attribute__ ((format (printf, 3, 4)));
static int vc_elf_close(VcElf *elf);

static int vc_elf_load_sce_module_info(VcElf *elf);

static int vc_dwarf_expression_evaluate(VcElf *elf, Dwarf_Op *ops, uint32_t ops_count, Dwarf_Frame *dwarf_frame, Dwarf_Attribute *location_attribute, VcFrameState *frame_state_at_entry, VcFrameState *frame_state, Dwarf_Die *function_die,
                                   uint64_t *out_result, DwarfExpressionResultType *out_result_type);
static int vc_dwarf_expression_push(DwarfExpressionState *expression_state, uint64_t value);
static int vc_dwarf_expression_pop(DwarfExpressionState *expression_state, uint64_t *out_value);

VcElf *vc_elf_new() {
	VcElf *elf = calloc(1, sizeof(VcElf));
	if (!elf) {
		return NULL;
	}

	elf->elf_fd = -1;

	return elf;
}

void vc_elf_free(VcElf *elf) {
	if (!elf) {
		return;
	}

	vc_elf_close(elf);

	FREE(elf->module_name);
	FREE(elf->filename);
	FREE(elf);
}

static int vc_elf_load_symbols(VcElf *elf) {
	size_t shdr_count = 0;
	if (elf_getshdrnum(elf->elf, &shdr_count) == -1) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get the section header count: %s", elf_errmsg(-1));
		goto error;
	}

	for (size_t i = 0; i < shdr_count; i++) {
		Elf_Scn *section = elf_getscn(elf->elf, i);
		if (!section) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get section %lu: %s", i, elf_errmsg(-1));
			goto error;
		}

		GElf_Shdr mem;
		GElf_Shdr *shdr = gelf_getshdr(section, &mem);
		if (!shdr) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get section header %lu: %s", i, elf_errmsg(-1));
			goto error;
		}

		if (shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM) {
			elf->symbols_data = elf_getdata(section, NULL);
			if (!elf->symbols_data) {
				vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Unable to get symbols section data: %s", elf_errmsg(-1));
				return -1;
			}

			elf->symbols_count                = shdr->sh_size / sizeof(Elf32_Sym);
			elf->symbols_string_table_index   = shdr->sh_link;
			break;
		}
	}

	if (elf->symbols_data) {
		Elf_Scn *section = elf_getscn(elf->elf, elf->symbols_string_table_index);
		if (!section) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get symbol string table section %lu: %s", elf->symbols_string_table_index, elf_errmsg(-1));
			goto error;
		}

		GElf_Shdr mem;
		GElf_Shdr *shdr = gelf_getshdr(section, &mem);
		if (!shdr) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get string table section header: %s", elf_errmsg(-1));
			goto error;
		}

		if (shdr->sh_type != SHT_STRTAB) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "The symbol's table section linked section is not a string table");
			goto error;
		}
	}

	return 0;

error:
	elf->symbols_data = NULL;
	elf->symbols_count = 0;
	elf->symbols_string_table_index = 0;

	return -1;
}

static int vc_elf_load_runtime_cfi(VcElf *elf) {
	size_t shdr_count = 0;
	if (elf_getshdrnum(elf->elf, &shdr_count) == -1) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get the section header count: %s", elf_errmsg(-1));
		goto error;
	}

	for (size_t i = 0; i < shdr_count; i++) {
		Elf_Scn *section = elf_getscn(elf->elf, i);
		if (!section) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get section %lu: %s", i, elf_errmsg(-1));
			goto error;
		}

		GElf_Shdr mem;
		GElf_Shdr *shdr = gelf_getshdr(section, &mem);
		if (!shdr) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get section header %lu: %s", i, elf_errmsg(-1));
			goto error;
		}

		if (shdr->sh_type == SHT_ARM_EXIDX) {
			elf->exidx_data = elf_getdata(section, NULL);
			if (!elf->exidx_data) {
				vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Unable to get exidx section data: %s", elf_errmsg(-1));
				return -1;
			}

			elf->exidx_start_address = shdr->sh_addr;
			break;
		}
	}

	return 0;

error:
	elf->exidx_data = NULL;
	elf->exidx_start_address = 0;
	elf->extab_data = NULL;

	return -1;
}

int vc_elf_load(VcElf *elf, const char *filename) {
	if (elf->loaded) {
		vc_elf_set_error(elf, VC_ELF_ERROR_ALREADY_LOADED, "An elf file is already loaded");
		goto error;
	}

	elf->filename = strdup(filename);

	elf_version(EV_CURRENT);

	elf->elf_fd = open(elf->filename, O_RDONLY);
	if (elf->elf_fd < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_OPEN_FAILED, "%s", strerror(errno));
		goto error;
	}

	elf->elf = elf_begin(elf->elf_fd, ELF_C_READ, NULL);
	if (!elf->elf) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to open elf file: %s", elf_errmsg(-1));
		goto error;
	}

	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr = gelf_getehdr(elf->elf, &ehdr_mem);
	if (!ehdr) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get the file header: %s", elf_errmsg(-1));
		goto error;
	}

	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN && ehdr->e_type != ET_SCE_EXEC && ehdr->e_type != ET_SCE_RELEXEC) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Invalid elf type: %d", ehdr->e_type);
		goto error;
	}

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32 || ehdr->e_ident[EI_DATA] != ELFDATA2LSB || ehdr->e_machine != EM_ARM) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "The elf is not for the 32-bit LE ARM architecture");
		goto error;
	}

	// Find the load virtual address
	size_t phdr_count = 0;
	if (elf_getphdrnum(elf->elf, &phdr_count) == -1) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get the program header count: %s", elf_errmsg(-1));
		goto error;
	}

	uint32_t base_address = 0xFFFFFFFF;
	uint32_t end_address = 0;
	for (size_t i = 0; i < phdr_count; i++) {
		GElf_Phdr mem;
		GElf_Phdr *phdr = gelf_getphdr(elf->elf, i, &mem);
		if (!phdr) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get program header %lu: %s", i, elf_errmsg(-1));
			goto error;
		}

		if (phdr->p_type != PT_LOAD) {
			continue;
		}

		if (phdr->p_vaddr < base_address) {
			base_address = phdr->p_vaddr;
		}
		uint32_t phdr_end_address = phdr->p_vaddr + phdr->p_memsz;
		if (phdr_end_address > end_address) {
			end_address = phdr_end_address;
		}
	}

	elf->base_address = base_address;
	elf->memory_size  = end_address - base_address;

	if (vc_elf_load_symbols(elf) < 0) {
		goto error;
	}

	if (vc_elf_load_runtime_cfi(elf) < 0) {
		goto error;
	}

	// Open the DWARF information
	elf->dwarf = dwarf_begin_elf(elf->elf, O_RDONLY, NULL);
	if (!elf->dwarf) {
		if (dwarf_errno() != ENXIO) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to read dwarf information: %s", dwarf_errmsg(-1));
			goto error;
		}
	}

	if (elf->dwarf) {
		elf->dwarf_cfi = dwarf_getcfi(elf->dwarf);
		if (!elf->dwarf_cfi) {
			elf->dwarf_cfi = dwarf_getcfi_elf(elf->elf);
		}
	}

	if (ehdr->e_type == ET_SCE_EXEC || ehdr->e_type == ET_SCE_RELEXEC) {
		if (vc_elf_load_sce_module_info(elf) < 0) {
			goto error;
		}
	}

	elf->loaded = true;

	return 0;

error:
	vc_elf_close(elf);
	FREE(elf->filename);
	elf->base_address = 0;

	return -1;
}

int vc_elf_get_error_code(VcElf *elf) {
	return elf->error_code;
}

const char *vc_elf_get_error_message(VcElf *elf) {
	return elf->error_message;
}

static void vc_elf_set_error(VcElf *elf, int code, const char *message, ...) {
	va_list args;
	va_start(args, message);

	elf->error_code = code;

	vsnprintf(elf->error_message, VC_ELF_ERROR_MESSAGE_SIZE, message, args);

	va_end(args);
}

static int vc_elf_close(VcElf *elf) {
	if (elf->dwarf_cfi && elf->dwarf_cfi_from_elf) {
		dwarf_cfi_end(elf->dwarf_cfi);
	}
	elf->dwarf_cfi = NULL;

	if (elf->dwarf) {
		dwarf_end(elf->dwarf);
		elf->dwarf = NULL;
	}

	if (elf->elf) {
		elf_end(elf->elf);
		elf->elf = NULL;
	}

	if (elf->elf_fd >= 0) {
		close(elf->elf_fd);
		elf->elf_fd = -1;
	}

	return 0;
}

int vc_elf_get_base_address(VcElf *elf, uint32_t *out_address) {
	if (!elf->loaded) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_LOADED, "No elf loaded");
		return -1;
	}

	*out_address = elf->base_address;

	return 0;
}

int vc_elf_get_module_name(VcElf *elf, const char **out_module_name) {
	if (!elf->loaded) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_LOADED, "No elf loaded");
		return -1;
	}

	*out_module_name = elf->module_name;

	return 0;
}

int vc_elf_get_memory_size(VcElf *elf, uint32_t *out_size) {
	if (!elf->loaded) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_LOADED, "No elf loaded");
		return -1;
	}

	*out_size = elf->memory_size;

	return 0;
}

static bool vc_elf_dwarf_tag_is_function(int tag) {
	return tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine || tag == DW_TAG_entry_point;
}

static int vc_elf_get_pc_info_dwarf(VcElf *elf, uint32_t address, VcAddressInfo *out_pc_info) {
	assert(elf->dwarf);

	Dwarf_Die cu_die_mem;
	Dwarf_Die *cu_die = dwarf_addrdie(elf->dwarf, address, &cu_die_mem);
	if (!cu_die) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No dwarf compilation unit DIE found for PC at %x", address);
		return -1;
	}

	const char *line_filename = NULL;
	int line_number = -1;

	Dwarf_Line *dwarf_line = dwarf_getsrc_die(cu_die, address);
	if (line_number) {
		Dwarf_Files *files;
		size_t file_idx;
		if (dwarf_line_file(dwarf_line, &files, &file_idx) < 0) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to retrieve the line's file: %s", dwarf_errmsg(-1));
			return -1;
		}

		line_filename = dwarf_filesrc(files, file_idx, NULL, NULL);
		if (!line_filename) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to retrieve the line's file name: %s", dwarf_errmsg(-1));
			return -1;
		}

		if (dwarf_lineno(dwarf_line, &line_number) < 0) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to retrieve the line's number: %s", dwarf_errmsg(-1));
			return -1;
		}
	}

	Dwarf_Die *scopes;
	int scopes_count = dwarf_getscopes(cu_die, address, &scopes);
	if (scopes_count < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to retrieve the scopes for PC %x: %s", address, dwarf_errmsg(-1));
		return -1;
	}

	const char *function_name = NULL;
	int function_offset = -1;

	if (scopes_count > 0) {
		Dwarf_Die *function_die = NULL;

		for (int i = 0; i < scopes_count; i++) {
			int tag = dwarf_tag(&scopes[i]);
			if (vc_elf_dwarf_tag_is_function(tag)) {
				function_die = &scopes[i];
				break;
			}
		}

		if (function_die) {
			function_name = dwarf_diename(function_die);

			size_t function_low_pc;
			if (dwarf_lowpc(function_die, &function_low_pc) >= 0) {
				function_offset = address - function_low_pc;
				assert(function_offset >= 0);
			}
		}

		free(scopes);
	}

	if (!line_filename && !function_name) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No information could be found for PC at %x", address);
		return -1;
	}

	out_pc_info->line_filename   = line_filename;
	out_pc_info->line_number     = line_number;
	out_pc_info->function_name   = function_name;
	out_pc_info->function_offset = function_offset;

	return 0;
}

static int vc_elf_get_pc_info_symbols(VcElf *elf, uint32_t address, VcAddressInfo *out_pc_info) {
	assert(elf->symbols_data);

	GElf_Sym symbol_mem;
	GElf_Sym *function_symbol = NULL;

	for (uint32_t symbol_index = 0; symbol_index < elf->symbols_count; symbol_index++) {
		GElf_Sym *symbol = gelf_getsym(elf->symbols_data, symbol_index, &symbol_mem);
		if (ELF32_ST_TYPE(symbol->st_info) != STT_FUNC) continue;

		if (address >= symbol->st_value && address < (symbol->st_value + symbol->st_size)) {
			function_symbol = symbol;
			break;
		}
	}

	if (function_symbol) {
		out_pc_info->function_name   = elf_strptr(elf->elf, elf->symbols_string_table_index, function_symbol->st_name);
		out_pc_info->function_offset = address - function_symbol->st_value;
		out_pc_info->line_filename   = NULL;
		out_pc_info->line_number     = -1;
		return 0;
	}

	vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No information could be found for PC at %x", address);
	return -1;
}

int vc_elf_get_pc_info(VcElf *elf, uint32_t address, VcAddressInfo *out_pc_info) {
	if (!elf->loaded) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_LOADED, "No elf loaded");
		return -1;
	}

	if (elf->dwarf) {
		if (vc_elf_get_pc_info_dwarf(elf, address, out_pc_info) >= 0) {
			return 0;
		}

		if (vc_elf_get_error_code(elf) != VC_ELF_ERROR_NOT_FOUND) {
			return -1;
		}
	}

	if (elf->symbols_data) {
		if (vc_elf_get_pc_info_symbols(elf, address, out_pc_info) >= 0) {
			return 0;
		}

		if (vc_elf_get_error_code(elf) != VC_ELF_ERROR_NOT_FOUND) {
			return -1;
		}
	}

	vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No information could be found for PC at %x", address);
	return -1;
}

static int vc_elf_find_section_at_address(VcElf *elf, uint32_t address, Elf_Data **out_data, uint32_t *out_base_address) {
	size_t shdr_count = 0;
	if (elf_getshdrnum(elf->elf, &shdr_count) == -1) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get the section header count: %s", elf_errmsg(-1));
		goto error;
	}

	for (size_t i = 0; i < shdr_count; i++) {
		Elf_Scn *section = elf_getscn(elf->elf, i);
		if (!section) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get section %lu: %s", i, elf_errmsg(-1));
			goto error;
		}

		GElf_Shdr mem;
		GElf_Shdr *shdr = gelf_getshdr(section, &mem);
		if (!shdr) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get section header %lu: %s", i, elf_errmsg(-1));
			goto error;
		}

		if (address >= shdr->sh_addr && address < (shdr->sh_addr + shdr->sh_size)) {
			*out_data = elf_getdata(section, NULL);
			if (!*out_data) {
				vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Unable to get section %lu data: %s", i, elf_errmsg(-1));
				return -1;
			}

			*out_base_address = shdr->sh_addr;
			return 0;
		}
	}

	vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No ELF section at address %x", address);

error:
	return -1;
}

static int vc_elf_runtime_cfi_get_next_script_byte(VcElf *elf, ExTabScript *script, uint8_t *out_byte) {
	if (script->remaining_bytes == 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Requesting more instruction bytes than available");
		return -1;
	}

	if (script->current_byte == 0) {
		script->instructions++;
		script->current_byte = 3;
	} else {
		script->current_byte--;
	}

	*out_byte = ((*script->instructions) >> (script->current_byte * 8)) & 0xFF;
	script->remaining_bytes--;

	return 0;
}

static int vc_elf_runtime_cfi_pop_register(VcElf *elf, uint8_t register_index, VcUnwindCallbacks *callbacks, VcFrameState *frame_state, uint32_t *vsp) {
	assert(register_index < 16);

	uint32_t register_value;
	if (callbacks->memory_read(callbacks->user_data, *vsp, &register_value) < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_MEMORY_READ_FAILED, "Failed to read memory at 0x%08x", *vsp);
		return -1;
	}

	frame_state->registers[register_index] = register_value;
	frame_state->registers_with_unknown_value &= ~(1 << register_index);
	*vsp += 4;

	return 0;
}

static int vc_elf_runtime_cfi_pop_starting_at_r4(VcElf *elf, uint8_t register_count, bool pop_r14, VcUnwindCallbacks *callbacks, VcFrameState *frame_state) {
	uint32_t vsp = frame_state->registers[ARM_REG_SP];

	for (int register_index = 4; register_index <= (4 + register_count); register_index++) {
		if (vc_elf_runtime_cfi_pop_register(elf, register_index, callbacks, frame_state, &vsp) < 0) {
			return -1;
		}
	}

	if (pop_r14) {
		if (vc_elf_runtime_cfi_pop_register(elf, ARM_REG_LR, callbacks, frame_state, &vsp) < 0) {
			return -1;
		}
	}

	frame_state->registers[ARM_REG_SP] = vsp;

	return 0;
}

static int vc_elf_runtime_cfi_pop_r0_to_r3(VcElf *elf, uint8_t register_mask, VcUnwindCallbacks *callbacks, VcFrameState *frame_state) {
	uint32_t vsp = frame_state->registers[ARM_REG_SP];

	for (int register_index = 0; register_index <= 3; register_index++) {
		if ((register_mask & (1 << register_index)) != 0) {
			if (vc_elf_runtime_cfi_pop_register(elf, register_index, callbacks, frame_state, &vsp) < 0) {
				return -1;
			}
		}
	}

	frame_state->registers[ARM_REG_SP] = vsp;

	return 0;
}

static int vc_elf_runtime_cfi_pop_r4_to_r15(VcElf *elf, uint16_t register_mask, VcUnwindCallbacks *callbacks, VcFrameState *frame_state) {
	uint32_t vsp = frame_state->registers[ARM_REG_SP];

	for (int register_index = 4; register_index <= 15; register_index++) {
		if ((register_mask & (1 << (register_index - 4))) != 0) {
			if (vc_elf_runtime_cfi_pop_register(elf, register_index, callbacks, frame_state, &vsp) < 0) {
				return -1;
			}
		}
	}

	frame_state->registers[ARM_REG_SP] = vsp;

	return 0;
}

static uint32_t vc_elf_translate_prel31(uint32_t *prel31, void *start, uint32_t start_address) {
	int32_t relative_address = ((((int32_t)(*prel31)) << 1) >> 1);
	return start_address + ((uint8_t *)prel31 - (uint8_t *)start) + relative_address;
}

static int vc_elf_runtime_cfi_setup_script(VcElf *elf, ExIdxEntry *frame_entry, ExTabScript *out_script) {
	// https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst#73the-arm-defined-compact-model
	if (frame_entry->instruction == 1) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Reached a can't unwind marker");
		return -1;
	}

	if (frame_entry->instruction & 0x80000000) {
		// In-line encoding
		out_script->instructions = &frame_entry->instruction;
		out_script->current_byte = 3;
		out_script->remaining_bytes = 3;
		return 0;
	}

	uint32_t extab_script_address = vc_elf_translate_prel31(&frame_entry->instruction, elf->exidx_data->d_buf, elf->exidx_start_address);

	if (!elf->extab_data || extab_script_address < elf->extab_start_address || extab_script_address >= (elf->extab_start_address + elf->extab_data->d_size)) {
		if (vc_elf_find_section_at_address(elf, extab_script_address, &elf->extab_data, &elf->extab_start_address) < 0) {
			return -1;
		}
	}

	// https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst#102personality-routine-exception-handling-table-entries
	uint32_t *extab_data = (uint32_t *)(elf->extab_data->d_buf + extab_script_address - elf->extab_start_address);
	uint32_t extab_first_word = *extab_data;
	bool compact_model = (extab_first_word & 0x80000000) != 0;
	if (compact_model) {
		int compact_personality_routine_index = (extab_first_word >> 24) & 0x7F;
		switch (compact_personality_routine_index) {
		case 0: {
			out_script->instructions = extab_data;
			out_script->current_byte = 3;
			out_script->remaining_bytes = 3;
			break;
		}
		case 1: {
			int extra_instruction_words = (extab_first_word >> 16) & 0xFF;
			out_script->instructions = extab_data;
			out_script->current_byte = 2;
			out_script->remaining_bytes = 2 + 4 * extra_instruction_words;
			break;
		}
		default:
			vc_elf_set_error(elf, VC_ELF_ERROR_NOT_IMPLEMENTED, "Unhandled compact mode personality routine index %d", compact_personality_routine_index);
			return -1;
		}

		// TODO: Check instructions don't go out of bounds
	} else {
		// GCC puts regular unwind data just after the personality routine address
		// TODO: Maybe check the personality routine is __gcc_personality_v0 by looking up the symbol
		extab_data++;

		int extra_instruction_words = ((*extab_data) >> 24) & 0xFF;
		out_script->instructions = extab_data;
		out_script->current_byte = 3;
		out_script->remaining_bytes = 3 + 4 * extra_instruction_words;
	}

	return 0;
}

static int vc_elf_runtime_cfi_execute_script(VcElf *elf, VcUnwindCallbacks *callbacks, ExTabScript *script, VcFrameState *frame_state) {
	uint32_t frame_pc = frame_state->registers[ARM_REG_PC];
	frame_state->registers[ARM_REG_PC] = 0; // Need to detect whether PC is set

	// https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst#103frame-unwinding-instructions
	while (script->remaining_bytes) {
		uint8_t instruction;
		if (vc_elf_runtime_cfi_get_next_script_byte(elf, script, &instruction) < 0) {
			return -1;
		}

		if ((instruction & 0xC0) == 0x00) {
			frame_state->registers[ARM_REG_SP] += ((instruction & 0x3F) << 2) + 4;
		} else if ((instruction & 0xC0) == 0x40) {
			frame_state->registers[ARM_REG_SP] -= ((instruction & 0x3F) << 2) + 4;
		} else if ((instruction & 0xF0) == 0x80) {
			uint8_t next_byte;
			if (vc_elf_runtime_cfi_get_next_script_byte(elf, script, &next_byte) < 0) {
				return -1;
			}
			if (instruction == 0x80 && next_byte == 0x00) {
				vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Reached a refuse to unwind instruction at PC %x", frame_pc);
				return -1;
			}

			uint16_t registers_mask = ((instruction & 0x0F) << 8) | next_byte;
			if (vc_elf_runtime_cfi_pop_r4_to_r15(elf, registers_mask, callbacks, frame_state) < 0) {
				return -1;
			}
		} else if ((instruction & 0xF0) == 0x90) {
			uint8_t register_index = instruction & 0x0F;
			if (register_index == ARM_REG_SP || register_index == ARM_REG_PC) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Reached reserved unwind instruction encoding at PC %x: %x", frame_pc, instruction);
				return -1;
			}

			frame_state->registers[ARM_REG_SP] = frame_state->registers[register_index];
		} else if ((instruction & 0xF0) == 0xA0) {
			bool pop_r14 = (instruction & 0x08) != 0;
			uint8_t register_count = (instruction & 0x07);

			if (vc_elf_runtime_cfi_pop_starting_at_r4(elf, register_count, pop_r14, callbacks, frame_state) < 0) {
				return -1;
			}
		} else if (instruction == 0xB0) {
			// Finish
			break;
		} else if (instruction == 0xB1) {
			uint8_t next_byte;
			if (vc_elf_runtime_cfi_get_next_script_byte(elf, script, &next_byte) < 0) {
				return -1;
			}

			if (next_byte == 0x00) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Reached spare unwind instruction encoding at PC %x: %x, %x", frame_pc, instruction, next_byte);
				return -1;
			}

			if ((next_byte & 0xF0) != 0) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Reached spare unwind instruction encoding at PC %x: %x, %x", frame_pc, instruction, next_byte);
				return -1;
			}

			uint16_t registers_mask = (next_byte & 0x0F);
			if (vc_elf_runtime_cfi_pop_r0_to_r3(elf, registers_mask, callbacks, frame_state) < 0) {
				return -1;
			}
		} else if (instruction == 0xB3) {
			uint8_t next_byte;
			if (vc_elf_runtime_cfi_get_next_script_byte(elf, script, &next_byte) < 0) {
				return -1;
			}

			// TODO: Update VFP registers
			uint8_t register_count = next_byte & 0x0F;
			frame_state->registers[ARM_REG_SP] += (register_count + 1) * 8 + 4;
		} else if ((instruction & 0xF8) == 0xB8) {
			// TODO: Update VFP registers
			uint8_t register_count = instruction & 0x07;
			frame_state->registers[ARM_REG_SP] += (register_count + 1) * 8 + 4;
		} else if (instruction == 0xC8) {
			uint8_t next_byte;
			if (vc_elf_runtime_cfi_get_next_script_byte(elf, script, &next_byte) < 0) {
				return -1;
			}
			// TODO: Update VFP registers
			uint8_t register_count = next_byte & 0x0F;
			frame_state->registers[ARM_REG_SP] += (register_count + 1) * 8;
		} else if (instruction == 0xC9) {
			uint8_t next_byte;
			if (vc_elf_runtime_cfi_get_next_script_byte(elf, script, &next_byte) < 0) {
				return -1;
			}
			// TODO: Update VFP registers
			uint8_t register_count = next_byte & 0x0F;
			frame_state->registers[ARM_REG_SP] += (register_count + 1) * 8;
		} else if ((instruction & 0xF8) == 0xD0) {
			// TODO: Update VFP registers
			uint8_t register_count = instruction & 0x07;
			frame_state->registers[ARM_REG_SP] += (register_count + 1) * 8;
		} else {
			vc_elf_set_error(elf, VC_ELF_ERROR_NOT_IMPLEMENTED, "Unhandled unwind instruction at PC %x: %x", frame_pc, instruction);
			return -1;
		}
	}

	// The finish instruction is always executed
	if (!frame_state->registers[ARM_REG_PC]) {
		frame_state->registers[ARM_REG_PC] = frame_state->registers[ARM_REG_LR];
	}

	return 0;
}

static int vc_elf_runtime_cfi_unwind_one_frame(VcElf *elf, VcUnwindCallbacks *callbacks, VcFrameState *frame_state, VcFrameState *out_caller_frame_state) {
	assert(elf->exidx_data);

	uint32_t frame_pc = frame_state->registers[ARM_REG_PC];

	ExIdxEntry *start = elf->exidx_data->d_buf;
	ExIdxEntry *end   = elf->exidx_data->d_buf + elf->exidx_data->d_size;

	ExIdxEntry *entry = start;
	ExIdxEntry *frame_entry = NULL;

	// TODO: Binary search
	while (entry != end) {
		uint32_t entry_start_pc = vc_elf_translate_prel31(&entry->address_offset, start, elf->exidx_start_address);

		if (entry_start_pc > frame_pc && entry != start) {
			frame_entry = entry - 1;
			break;
		}
		entry++;
	}

	if (!frame_entry) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No runtime CFI information at PC %x", frame_pc);
		return -1;
	}

	ExTabScript script;
	if (vc_elf_runtime_cfi_setup_script(elf, frame_entry, &script) < 0) {
		return -1;
	}

	memcpy(out_caller_frame_state->registers, &frame_state->registers, sizeof(out_caller_frame_state->registers));

	// Assume r0-r3 are clobbered as they are not callee-saved
	out_caller_frame_state->registers_with_unknown_value = 0x000F;

	if (vc_elf_runtime_cfi_execute_script(elf, callbacks, &script, out_caller_frame_state) < 0) {
		return -1;
	}

	return 0;
}

static int vc_elf_dwarf_unwind_one_register(VcElf *elf, VcUnwindCallbacks *callbacks, Dwarf_Frame *dwarf_frame, VcFrameState *frame_state, uint32_t register_index, uint32_t *out_caller_value) {
	Dwarf_Op ops_mem[3];
	uint32_t frame_pc = frame_state->registers[ARM_REG_PC];

	Dwarf_Op *ops;
	size_t ops_count;
	if (dwarf_frame_register(dwarf_frame, register_index, ops_mem, &ops, &ops_count) < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No CFI for register %d at PC %x: %s", register_index, frame_pc, dwarf_errmsg(-1));
		return -1;
	}

	if (!ops_count && ops == ops_mem) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Unable to unwind register %d at PC %x, it is clobbered", register_index, frame_pc);
		return -1;
	}

	if (!ops_count && !ops) {
		// The value is unchanged
		if (frame_state->registers_with_unknown_value & (1 << register_index)) {
			vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Unable to unwind register %d at PC %x, it is clobbered", register_index, frame_pc);
			return -1;
		}

		*out_caller_value = frame_state->registers[register_index];
		return 0;
	}

	uint64_t expression_result;
	DwarfExpressionResultType result_type;
	if (vc_dwarf_expression_evaluate(elf, ops, ops_count, dwarf_frame, NULL, NULL, frame_state, NULL, &expression_result, &result_type) < 0) {
		return -1;
	}

	if (result_type == DwarfExpressionResultTypeValue) {
		*out_caller_value = expression_result;
		return 0;
	}

	if (result_type == DwarfExpressionResultTypeAddress) {
		if (callbacks->memory_read(callbacks->user_data, expression_result, out_caller_value) < 0) {
			vc_elf_set_error(elf, VC_ELF_ERROR_MEMORY_READ_FAILED, "Failed to read memory at 0x%08lx", expression_result);
			return -1;
		}

		return 0;
	}

	vc_elf_set_error(elf, VC_ELF_ERROR_NOT_IMPLEMENTED, "Unhandled dward expression result type: %d", result_type);
	return -1;
}

static int vc_elf_dwarf_unwind_one_frame(VcElf *elf, VcUnwindCallbacks *callbacks, VcFrameState *frame_state, VcFrameState *out_caller_frame_state) {
	assert(elf->dwarf_cfi);

	uint32_t frame_pc = frame_state->registers[ARM_REG_PC];

	Dwarf_Frame *dwarf_frame = NULL;
	if (dwarf_cfi_addrframe(elf->dwarf_cfi, frame_pc, &dwarf_frame) < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No CFI information at PC %x: %s", frame_pc, dwarf_errmsg(-1));
		goto error;
	}

	int ra_reg_idx = dwarf_frame_info(dwarf_frame, NULL, NULL, NULL);
	if (ra_reg_idx < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No return address register index found: %s", dwarf_errmsg(-1));
		goto error;
	}
	assert(ra_reg_idx == ARM_REG_LR);

	out_caller_frame_state->registers_with_unknown_value = 0xFFFF;

	for (int register_index = 0; register_index < ARM_REG_PC; register_index++) {
		uint32_t caller_value;
		if (vc_elf_dwarf_unwind_one_register(elf, callbacks, dwarf_frame, frame_state, register_index, &caller_value) < 0) {
			if (register_index == ra_reg_idx || register_index == ARM_REG_SP) {
				// LR and SP are required to keep unwinding
				goto error;
			}

			continue;
		}

		if (register_index == ra_reg_idx) {
			out_caller_frame_state->registers[ARM_REG_PC] = caller_value - 4;
			out_caller_frame_state->registers_with_unknown_value &= ~(1 << ARM_REG_PC);
		} else {
			out_caller_frame_state->registers[register_index] = caller_value;
			out_caller_frame_state->registers_with_unknown_value &= ~(1 << register_index);
		}
	}

	free(dwarf_frame);
	return 0;

error:
	free(dwarf_frame);
	return -1;
}

int vc_elf_unwind_one_frame(VcElf *elf, VcUnwindCallbacks *callbacks, VcFrameState *frame_state, VcFrameState *out_caller_frame_state) {
	if (!elf->loaded) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_LOADED, "No elf loaded");
		return -1;
	}

	if (elf->dwarf_cfi) {
		if (vc_elf_dwarf_unwind_one_frame(elf, callbacks, frame_state, out_caller_frame_state) >= 0) {
			return 0;
		}

		if (vc_elf_get_error_code(elf) != VC_ELF_ERROR_NOT_FOUND) {
			return -1;
		}
	}

	if (elf->exidx_data) {
		if (vc_elf_runtime_cfi_unwind_one_frame(elf, callbacks, frame_state, out_caller_frame_state) >= 0) {
			return 0;
		}

		if (vc_elf_get_error_code(elf) != VC_ELF_ERROR_NOT_FOUND) {
			return -1;
		}
	}

	vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No CFI information available");
	return -1;
}

static int vc_dwarf_expression_push(DwarfExpressionState *expression_state, uint64_t value) {
	if (expression_state->stack_position >= DWARF_EXPRESSION_MAX_STACK) {
		return -1;
	}

	expression_state->stack[expression_state->stack_position] = value;
	expression_state->stack_position++;

	return 0;
}

static int vc_dwarf_expression_pop(DwarfExpressionState *expression_state, uint64_t *out_value) {
	if (expression_state->stack_position == 0) {
		return -1;
	}

	expression_state->stack_position--;
	*out_value = expression_state->stack[expression_state->stack_position];

	return 0;
}

static int vc_dwarf_expression_evaluate(VcElf *elf, Dwarf_Op *ops, uint32_t ops_count, Dwarf_Frame *dwarf_frame, Dwarf_Attribute *location_attribute, VcFrameState *frame_state_at_entry, VcFrameState *frame_state, Dwarf_Die *function_die,
                                        uint64_t *out_result, DwarfExpressionResultType *out_result_type) {
	DwarfExpressionState expression_state = { 0 };
	Dwarf_Op *op = NULL;

	*out_result_type = DwarfExpressionResultTypeAddress;

	for (size_t op_index = 0; op_index < ops_count; op_index++) {
		op = &ops[op_index];

		switch (op->atom) {
		case DW_OP_const1u:
		case DW_OP_const1s:
		case DW_OP_const2u:
		case DW_OP_const2s:
		case DW_OP_const4u:
		case DW_OP_const4s:
		case DW_OP_const8u:
		case DW_OP_const8s:
		case DW_OP_constu:
		case DW_OP_consts:
			if (vc_dwarf_expression_push(&expression_state, op->number) < 0) goto bad_push;
			break;
		case DW_OP_plus_uconst: {
			uint64_t value;
			if (vc_dwarf_expression_pop(&expression_state, &value) < 0) goto bad_pop;

			value += op->number;

			if (vc_dwarf_expression_push(&expression_state, value) < 0) goto bad_push;
			break;
		}
		case DW_OP_lit0:
		case DW_OP_lit1:
		case DW_OP_lit2:
		case DW_OP_lit3:
		case DW_OP_lit4:
		case DW_OP_lit5:
		case DW_OP_lit6:
		case DW_OP_lit7:
		case DW_OP_lit8:
		case DW_OP_lit9:
		case DW_OP_lit10:
		case DW_OP_lit11:
		case DW_OP_lit12:
		case DW_OP_lit13:
		case DW_OP_lit14:
		case DW_OP_lit15:
		case DW_OP_lit16:
		case DW_OP_lit17:
		case DW_OP_lit18:
		case DW_OP_lit19:
		case DW_OP_lit20:
		case DW_OP_lit21:
		case DW_OP_lit22:
		case DW_OP_lit23:
		case DW_OP_lit24:
		case DW_OP_lit25:
		case DW_OP_lit26:
		case DW_OP_lit27:
		case DW_OP_lit28:
		case DW_OP_lit29:
		case DW_OP_lit30:
		case DW_OP_lit31: {
			int value = op->atom - DW_OP_lit0;

			if (vc_dwarf_expression_push(&expression_state, value) < 0) goto bad_push;
			break;
		}
		case DW_OP_reg0:
		case DW_OP_reg1:
		case DW_OP_reg2:
		case DW_OP_reg3:
		case DW_OP_reg4:
		case DW_OP_reg5:
		case DW_OP_reg6:
		case DW_OP_reg7:
		case DW_OP_reg8:
		case DW_OP_reg9:
		case DW_OP_reg10:
		case DW_OP_reg11:
		case DW_OP_reg12:
		case DW_OP_reg13:
		case DW_OP_reg14:
		case DW_OP_reg15:
		case DW_OP_reg16:
		case DW_OP_reg17:
		case DW_OP_reg18:
		case DW_OP_reg19:
		case DW_OP_reg20:
		case DW_OP_reg21:
		case DW_OP_reg22:
		case DW_OP_reg23:
		case DW_OP_reg24:
		case DW_OP_reg25:
		case DW_OP_reg26:
		case DW_OP_reg27:
		case DW_OP_reg28:
		case DW_OP_reg29:
		case DW_OP_reg30:
		case DW_OP_reg31: {
			assert(ops_count == 1);

			int reg = op->atom - DW_OP_reg0;

			if (reg >= ARM_REG_COUNT) goto bad_register;

			if (vc_dwarf_expression_push(&expression_state, reg) < 0) goto bad_push;
			*out_result_type = DwarfExpressionResultTypeRegister;

			break;
		}
		case DW_OP_regx: {
			assert(ops_count == 1);

			if (op->number >= ARM_REG_COUNT) goto bad_register;

			if (vc_dwarf_expression_push(&expression_state, op->number) < 0) goto bad_push;
			*out_result_type = DwarfExpressionResultTypeRegister;

			break;
		}
		case DW_OP_fbreg: {
			if (!function_die) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Dwarf Op requested FB reg but function is available");
				return -1;
			}

			Dwarf_Attribute frame_base_mem;
			Dwarf_Attribute *frame_base_attribute = dwarf_attr_integrate(function_die, DW_AT_frame_base, &frame_base_mem);
			if (!frame_base_attribute) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the frame base attribute for function '%s': %s", dwarf_diename(function_die), dwarf_errmsg(-1));
				return -1;
			}

			Dwarf_Op *frame_base_ops;
			size_t frame_base_ops_count;
			if (dwarf_getlocation(frame_base_attribute, &frame_base_ops, &frame_base_ops_count) < 0) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get frame base ops: %s", dwarf_errmsg(-1));
				return -1;
			}

			uint64_t frame_base;
			DwarfExpressionResultType frame_base_type;
			if (vc_dwarf_expression_evaluate(elf, frame_base_ops, frame_base_ops_count, dwarf_frame, frame_base_attribute, frame_state_at_entry, frame_state, NULL, &frame_base, &frame_base_type) < 0) {
				return -1;
			}

			assert(frame_base_type == DwarfExpressionResultTypeAddress);

			uint32_t value = frame_base + op->number;

			if (vc_dwarf_expression_push(&expression_state, value) < 0) goto bad_push;
			break;
		}
		case DW_OP_breg0:
		case DW_OP_breg1:
		case DW_OP_breg2:
		case DW_OP_breg3:
		case DW_OP_breg4:
		case DW_OP_breg5:
		case DW_OP_breg6:
		case DW_OP_breg7:
		case DW_OP_breg8:
		case DW_OP_breg9:
		case DW_OP_breg10:
		case DW_OP_breg11:
		case DW_OP_breg12:
		case DW_OP_breg13:
		case DW_OP_breg14:
		case DW_OP_breg15:
		case DW_OP_breg16:
		case DW_OP_breg17:
		case DW_OP_breg18:
		case DW_OP_breg19:
		case DW_OP_breg20:
		case DW_OP_breg21:
		case DW_OP_breg22:
		case DW_OP_breg23:
		case DW_OP_breg24:
		case DW_OP_breg25:
		case DW_OP_breg26:
		case DW_OP_breg27:
		case DW_OP_breg28:
		case DW_OP_breg29:
		case DW_OP_breg30:
		case DW_OP_breg31: {
			int reg = op->atom - DW_OP_breg0;

			if (reg >= ARM_REG_COUNT) goto bad_register;

			if (frame_state->registers_with_unknown_value & (1 << reg)) {
				goto clobbered_register;
			}

			uint32_t value = frame_state->registers[reg] + op->number;

			if (vc_dwarf_expression_push(&expression_state, value) < 0) goto bad_push;
			break;
		}
		case DW_OP_bregx: {
			if (op->number >= ARM_REG_COUNT) goto bad_register;

			if (frame_state->registers_with_unknown_value & (1 << op->number)) {
				goto clobbered_register;
			}

			uint32_t value = frame_state->registers[op->number] + op->number2;

			if (vc_dwarf_expression_push(&expression_state, value) < 0) goto bad_push;
			break;
		}
		case DW_OP_call_frame_cfa: {
			if (!dwarf_frame) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Dwarf Op requested CFA but no frame is available");
				return -1;
			}

			Dwarf_Op *cfa_ops;
			size_t cfa_ops_count;
			if (dwarf_frame_cfa(dwarf_frame, &cfa_ops, &cfa_ops_count) < 0) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get CFA ops: %s", dwarf_errmsg(-1));
				return -1;
			}

			uint64_t cfa;
			DwarfExpressionResultType cfa_type;
			if (vc_dwarf_expression_evaluate(elf, cfa_ops, cfa_ops_count, NULL, NULL, frame_state_at_entry, frame_state, function_die, &cfa, &cfa_type) < 0) {
				return -1;
			}
			assert(cfa_type == DwarfExpressionResultTypeAddress);

			if (vc_dwarf_expression_push(&expression_state, cfa) < 0) goto bad_push;
			break;
		}
		case DW_OP_implicit_value:
			if (!location_attribute) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Dwarf Op requested entry value expression but no location attribute is available");
				return -1;
			}

			Dwarf_Block implicit_value;
			if (dwarf_getlocation_implicit_value(location_attribute, op, &implicit_value) < 0) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "No implicit value found: %s", dwarf_errmsg(-1));
				return -1;
			}

			if (implicit_value.length > 8) {
				vc_elf_set_error(elf, VC_ELF_ERROR_NOT_IMPLEMENTED, "Unhandled large implicit value");
				return -1;
			}

			uint64_t value = 0;
			memcpy(&value, implicit_value.data, implicit_value.length);
			*out_result_type = DwarfExpressionResultTypeValue;

			if (vc_dwarf_expression_push(&expression_state, value) < 0) goto bad_push;
			break;
		case DW_OP_stack_value: {
			if (vc_dwarf_expression_pop(&expression_state, out_result) < 0) goto bad_pop;
			*out_result_type = DwarfExpressionResultTypeValue;
			return 0;
		}
		case DW_OP_GNU_entry_value: {
			if (!frame_state_at_entry) {
				vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Optimized out - Function entry state not available");
				return -1;
			}

			if (!location_attribute) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Dwarf Op requested entry value expression but no location attribute is available");
				return -1;
			}

			Dwarf_Attribute entry_value_attribute;
			if (dwarf_getlocation_attr(location_attribute, op, &entry_value_attribute) < 0) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "No entry value expression attribute found: %s", dwarf_errmsg(-1));
				return -1;
			}

			Dwarf_Op *entry_value_ops;
			size_t entry_value_ops_count;
			if (dwarf_getlocation(&entry_value_attribute, &entry_value_ops, &entry_value_ops_count) < 0) {
				vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get entry value ops: %s", dwarf_errmsg(-1));
				return -1;
			}

			uint64_t entry_value;
			DwarfExpressionResultType entry_value_type;
			if (vc_dwarf_expression_evaluate(elf, entry_value_ops, entry_value_ops_count, dwarf_frame, NULL, NULL, frame_state_at_entry, function_die, &entry_value, &entry_value_type) < 0) {
				return -1;
			}

			uint32_t value;
			if (entry_value_type == DwarfExpressionResultTypeRegister) {
				if (entry_value >= ARM_REG_COUNT) goto bad_register;

				if (frame_state_at_entry->registers_with_unknown_value & (1 << entry_value)) {
					goto clobbered_register;
				}

				value = frame_state_at_entry->registers[entry_value];
			} else {
				value = entry_value;
			}

			if (vc_dwarf_expression_push(&expression_state, value) < 0) goto bad_push;

			break;
		}
		default:
			vc_elf_set_error(elf, VC_ELF_ERROR_NOT_IMPLEMENTED, "Dwarf Op not implemented 0x%x", op->atom);
			return -1;
		}
	}

	if (vc_dwarf_expression_pop(&expression_state, out_result) < 0) goto bad_pop;

	return 0;

clobbered_register:
	vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Optimized out - Register is clobbered");
	return -1;

bad_register:
	vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Invalid ARM register");
	return -1;

bad_push:
	vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Dwarf expression requires too much stack");
	return -1;

bad_pop:
	vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Dwarf expression tried to pop an empty stack");
	return -1;
}

static void vc_elf_variable_set_error(VcVariableInfo *variable, const char *message, ...) {
	va_list args;
	va_start(args, message);

	variable->location_type = VcVariableLocationTypeError;
	vsnprintf(variable->error_message, VC_ELF_ERROR_MESSAGE_SIZE, message, args);

	va_end(args);
}

static int vc_elf_get_type_info(VcElf *elf, Dwarf_Die *die, const char *context_name, DwarfTypeInfo *out_info) {
	Dwarf_Attribute type_attribute_mem;
	Dwarf_Attribute *type_attribute = dwarf_attr_integrate(die, DW_AT_type, &type_attribute_mem);
	if (!type_attribute) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the type attribute for local variable '%s'", context_name);
		return -1;
	}

	Dwarf_Die local_variable_type_die_mem;
	Dwarf_Die *local_variable_type_die = dwarf_formref_die(type_attribute, &local_variable_type_die_mem);
	if (!local_variable_type_die) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to dereference the type attribute for local variable '%s'", context_name);
		return -1;
	}

	Dwarf_Die base_type_die;
	if (dwarf_peel_type(local_variable_type_die, &base_type_die) < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to peel the local variable type");
		return -1;
	}

	Dwarf_Word type_encoding = 0;
	Dwarf_Word type_size = 0;
	int type_tag = dwarf_tag(&base_type_die);

	switch (type_tag) {
	case DW_TAG_array_type: {
		Dwarf_Die array_child;
		if (dwarf_child(&base_type_die, &array_child) < 0) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Array variable '%s' has no Dwarf child DIE", context_name);
			return -1;
		}

		// TODO: Make sure there are no other children

		int array_child_tag = dwarf_tag(&array_child);
		if (array_child_tag != DW_TAG_subrange_type) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Array variable '%s' Dwarf child DIE has type %x", context_name, array_child_tag);
			return -1;
		}

		Dwarf_Word lower_bound = 0;

		Dwarf_Attribute lower_bound_attribute_mem;
		Dwarf_Attribute *lower_bound_attribute = dwarf_attr_integrate(&array_child, DW_AT_lower_bound, &lower_bound_attribute_mem);
		if (lower_bound_attribute) {
			dwarf_formudata(lower_bound_attribute, &lower_bound);
		}

		Dwarf_Attribute upper_bound_attribute_mem;
		Dwarf_Attribute *upper_bound_attribute = dwarf_attr_integrate(&array_child, DW_AT_upper_bound, &upper_bound_attribute_mem);
		if (!upper_bound_attribute) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the upper bound attribute for local variable '%s'", context_name);
			return -1;
		}

		Dwarf_Word upper_bound;
		if (dwarf_formudata(upper_bound_attribute, &upper_bound) < 0) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the upper bound form for local variable '%s'", context_name);
			return -1;
		}

		if (upper_bound < lower_bound) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "The array upper bound %ld is less than the lower bound %ld for local variable '%s'", upper_bound, lower_bound, context_name);
			return -1;
		}

		Dwarf_Word element_count = upper_bound - lower_bound + 1;

		Dwarf_Word element_size = 0;

		Dwarf_Attribute element_size_attribute_mem;
		Dwarf_Attribute *element_size_attribute = dwarf_attr_integrate(&array_child, DW_AT_byte_size, &element_size_attribute_mem);
		if (element_size_attribute) {
			dwarf_formudata(element_size_attribute, &element_size);
		} else {
			DwarfTypeInfo element_info;
			if (vc_elf_get_type_info(elf, &base_type_die, context_name, &element_info) < 0) {
				return -1;
			}

			element_size = element_info.size;
		}

		type_size = element_count * element_size;
		break;
	}
	case DW_TAG_enumeration_type: {
		Dwarf_Attribute size_attribute_mem;
		Dwarf_Attribute *size_attribute = dwarf_attr_integrate(&base_type_die, DW_AT_byte_size, &size_attribute_mem);
		if (size_attribute) {
			dwarf_formudata(size_attribute, &type_size);
		} else {
			DwarfTypeInfo underlying_type_info;
			if (vc_elf_get_type_info(elf, &base_type_die, context_name, &underlying_type_info) < 0) {
				return -1;
			}

			type_size = underlying_type_info.size;
		}

		break;
	}
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
		type_size = 4;
		break;
	case DW_TAG_base_type: {
		Dwarf_Attribute encoding_attribute_mem;
		Dwarf_Attribute *encoding_attribute = dwarf_attr_integrate(&base_type_die, DW_AT_encoding, &encoding_attribute_mem);
		if (!encoding_attribute) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the type encoding attribute for local variable '%s'", context_name);
			return -1;
		}

		if (dwarf_formudata(encoding_attribute, &type_encoding) < 0) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the type encoding form for local variable '%s'", context_name);
			return -1;
		}

		Dwarf_Attribute size_attribute_mem;
		Dwarf_Attribute *size_attribute = dwarf_attr_integrate(&base_type_die, DW_AT_byte_size, &size_attribute_mem);
		if (!size_attribute) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the type size attribute for local variable '%s'", context_name);
			return -1;
		}

		if (dwarf_formudata(size_attribute, &type_size) < 0) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the type size form for local variable '%s'", context_name);
			return -1;
		}

		break;
	}
	case DW_TAG_structure_type:
	case DW_TAG_class_type:
	case DW_TAG_union_type: {
		Dwarf_Attribute size_attribute_mem;
		Dwarf_Attribute *size_attribute = dwarf_attr_integrate(&base_type_die, DW_AT_byte_size, &size_attribute_mem);
		if (!size_attribute) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the type size attribute for local variable '%s'", context_name);
			return -1;
		}

		if (dwarf_formudata(size_attribute, &type_size) < 0) {
			vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the type size form for local variable '%s'", context_name);
			return -1;
		}
		break;
	}
	default:
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_IMPLEMENTED, "Unhandled DIE type %x for local variable '%s'", type_tag, context_name);
		return -1;
	}

	out_info->tag      = type_tag;
	out_info->size     = type_size;
	out_info->encoding = type_encoding;

	return 0;
}

static int vc_elf_handle_local_variable(VcElf *elf, uint32_t address, VcFrameState *frame_state_at_entry, VcFrameState *frame_state, Dwarf_Frame *dwarf_frame, Dwarf_Die *local_variable_die, Dwarf_Die *function_die, VcVariableInfo *out_variable_info) {
	int die_tag = dwarf_tag(local_variable_die);
	if (die_tag != DW_TAG_variable && die_tag != DW_TAG_formal_parameter) {
		return -1;
	}

	const char *local_variable_name = dwarf_diename(local_variable_die);
	if (!local_variable_name) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get local variable name");
		return -1;
	}

	out_variable_info->name = local_variable_name;

	DwarfTypeInfo type_info;
	if (vc_elf_get_type_info(elf, local_variable_die, local_variable_name, &type_info) < 0) {
		return -1;
	}

	out_variable_info->size = type_info.size;

	switch (type_info.tag) {
	case DW_TAG_enumeration_type:
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
		out_variable_info->type = VcVariableTypeInteger;
		break;
	case DW_TAG_base_type:
		switch (type_info.encoding) {
		case DW_ATE_signed:
		case DW_ATE_signed_char:
		case DW_ATE_unsigned:
		case DW_ATE_unsigned_char:
		case DW_ATE_boolean:
		case DW_ATE_address:
			out_variable_info->type = VcVariableTypeInteger;
			break;
		case DW_ATE_float:
			out_variable_info->type = VcVariableTypeFloat;
			break;
		default:
			out_variable_info->type = VcVariableTypeUnhandled;
			break;
		}
		break;
	default:
		out_variable_info->type = VcVariableTypeUnhandled;
		break;
	}

	Dwarf_Attribute location_attribute_mem;
	Dwarf_Attribute *location_attribute = dwarf_attr_integrate(local_variable_die, DW_AT_location, &location_attribute_mem);
	if (!location_attribute) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the location attribute for local variable '%s'", local_variable_name);
		return -1;
	}

	Dwarf_Op *exprs[1];
	size_t exprlens[1];
	int expressions_count = dwarf_getlocation_addr(location_attribute, address, exprs, exprlens, 1);
	if (expressions_count < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Unable to get the location expression for local variable '%s'", local_variable_name);
		return -1;
	}

	if (expressions_count == 0) {
		vc_elf_variable_set_error(out_variable_info, "Optimized out - Not available at this PC");
		return 0;
	}

	uint64_t result;
	DwarfExpressionResultType result_type;
	if (vc_dwarf_expression_evaluate(elf, exprs[0], exprlens[0], dwarf_frame, location_attribute, frame_state_at_entry, frame_state, function_die, &result, &result_type) < 0) {
		vc_elf_variable_set_error(out_variable_info, "%s", vc_elf_get_error_message(elf));
		return 0;
	}

	switch (result_type) {
	case DwarfExpressionResultTypeAddress:
		out_variable_info->location_type = VcVariableLocationTypeMemory;
		out_variable_info->location = result;
		break;
	case DwarfExpressionResultTypeValue:
		out_variable_info->location_type = VcVariableLocationTypeValue;
		out_variable_info->location = result;
		break;
	case DwarfExpressionResultTypeRegister:
		if (frame_state->registers_with_unknown_value & (1 << result)) {
			vc_elf_variable_set_error(out_variable_info, "Optimized out - Register r%d is clobbered", result);
		} else {
			out_variable_info->location_type = VcVariableLocationTypeValue;
			out_variable_info->location = frame_state->registers[result];
		}
		break;
	}

	return 0;
}

static void vc_elf_add_variable_to_array(VcVariableInfo *variable, VcVariableInfo **variables, uint32_t *variable_count) {
	if (!*variable_count) {
		*variables = malloc(sizeof(VcVariableInfo));
	} else {
		*variables = realloc(*variables, sizeof(VcVariableInfo) * ((*variable_count) + 1));
	}

	memcpy(*variables + *variable_count, variable, sizeof(VcVariableInfo));
	*variable_count += 1;
}

int vc_elf_get_local_variables_at_pc(VcElf *elf, uint32_t address, VcFrameState *frame_state_at_entry, VcFrameState *frame_state, VcVariableInfo **out_variable_infos, uint32_t *out_variable_count) {
	if (!elf->loaded) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_LOADED, "No elf loaded");
		return -1;
	}

	if (!elf->dwarf) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No dwarf information");
		return -1;
	}

	Dwarf_Die cu_die_mem;
	Dwarf_Die *cu_die = dwarf_addrdie(elf->dwarf, address, &cu_die_mem);
	if (!cu_die) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No dwarf compilation unit DIE found for PC at %x", address);
		return -1;
	}

	Dwarf_Die *scopes;
	int scopes_count = dwarf_getscopes(cu_die, address, &scopes);
	if (scopes_count < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to retrieve the scopes for PC %x: %s", address, dwarf_errmsg(-1));
		return -1;
	}

	if (scopes_count == 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No scopes found");
		return -1;
	}

	Dwarf_Die *function_die = NULL;
	for (int i = 0; i < scopes_count; i++) {
		int tag = dwarf_tag(&scopes[i]);
		if (vc_elf_dwarf_tag_is_function(tag)) {
			function_die = &scopes[i];
			break;
		}
	}

	Dwarf_Frame *dwarf_frame = NULL;
	if (dwarf_cfi_addrframe(elf->dwarf_cfi, address, &dwarf_frame) < 0) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "No CFI information at PC %x: %s", address, dwarf_errmsg(-1));
		return -1;
	}

	*out_variable_count = 0;
	*out_variable_infos = 0;

	bool reached_function = false;
	for (int i = 0; i < scopes_count && !reached_function; i++) {
		Dwarf_Die *scope = &scopes[i];

		int scope_tag = dwarf_tag(scope);
		if (vc_elf_dwarf_tag_is_function(scope_tag)) {
			reached_function = true;
		}

		Dwarf_Die scope_child;
		if (dwarf_child(scope, &scope_child) < 0) {
			continue;
		}

		VcVariableInfo variable_info;
		if (vc_elf_handle_local_variable(elf, address, frame_state_at_entry, frame_state, dwarf_frame, &scope_child, function_die, &variable_info) >= 0) {
			vc_elf_add_variable_to_array(&variable_info, out_variable_infos, out_variable_count);
		}

		while (dwarf_siblingof(&scope_child, &scope_child) == 0) {
			if (vc_elf_handle_local_variable(elf, address, frame_state_at_entry, frame_state, dwarf_frame, &scope_child, function_die, &variable_info) >= 0) {
				vc_elf_add_variable_to_array(&variable_info, out_variable_infos, out_variable_count);
			}
		}
	}

	FREE(dwarf_frame);
	FREE(scopes);

	return 0;
}

int vc_elf_load_sce_module_info(VcElf *elf) {
	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr = gelf_getehdr(elf->elf, &ehdr_mem);
	if (!ehdr) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get the file header: %s", elf_errmsg(-1));
		goto error;
	}

	GElf_Phdr mem;
	GElf_Phdr *phdr = gelf_getphdr(elf->elf, 0, &mem);
	if (!phdr) {
		vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Failed to get program header %u: %s", 0, elf_errmsg(-1));
		goto error;
	}

	Elf_Data *module_info_data = elf_getdata_rawchunk(elf->elf, phdr->p_offset + ehdr->e_entry, sizeof(SceModuleInfo), ELF_T_BYTE);

	SceModuleInfo *module_info = (SceModuleInfo *)module_info_data->d_buf;

	elf->module_name = strdup(module_info->name);

	if (!elf->exidx_data && module_info->exidx_top) {
		elf->exidx_data = elf_getdata_rawchunk(elf->elf, phdr->p_offset + module_info->exidx_top, module_info->exidx_end - module_info->exidx_top, ELF_T_BYTE);
		elf->exidx_start_address = phdr->p_vaddr + module_info->exidx_top;
	}

	if (!elf->extab_data && module_info->extab_top) {
		elf->extab_data = elf_getdata_rawchunk(elf->elf, phdr->p_offset + module_info->extab_top, module_info->extab_end - module_info->extab_top, ELF_T_BYTE);
		elf->extab_start_address = phdr->p_vaddr + module_info->extab_top;
	}

	return 0;

error:
	FREE(elf->module_name);
	return -1;
}
