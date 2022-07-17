#include "vc_elf.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dwarf.h>
#include <elfutils/libdw.h>

#define ERROR_MESSAGE_SIZE 2048

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

	int error_code;
	char error_message[ERROR_MESSAGE_SIZE];
} VcElf;

typedef struct DwarfExpressionState {
	uint32_t stack[DWARF_EXPRESSION_MAX_STACK];
	uint32_t stack_position;
} DwarfExpressionState;

typedef struct ExIdxEntry {
	uint32_t address_offset;
	uint32_t instruction;
} ExIdxEntry;

typedef struct ExTabScript {
	uint32_t *instructions;
	int current_byte;
	int remaining_bytes;
} ExTabScript;

static void vc_elf_set_error(VcElf *elf, int code, const char *message, ...) __attribute__ ((format (printf, 3, 4)));
static int vc_elf_close(VcElf *elf);

static int vc_dwarf_expression_evaluate(VcElf *elf, Dwarf_Op *ops, uint32_t ops_count, Dwarf_Frame *dwarf_frame, VcFrameState *frame_state,
                                   uint32_t *out_result, bool *out_is_location);
static int vc_dwarf_expression_push(DwarfExpressionState *expression_state, uint32_t value);
static int vc_dwarf_expression_pop(DwarfExpressionState *expression_state, uint32_t *out_value);

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

	if (ehdr->e_type == ET_NONE || ehdr->e_type == ET_CORE) {
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

	vsnprintf(elf->error_message, ERROR_MESSAGE_SIZE, message, args);

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


int vc_elf_get_memory_size(VcElf *elf, uint32_t *out_size) {
	if (!elf->loaded) {
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_LOADED, "No elf loaded");
		return -1;
	}

	*out_size = elf->memory_size;

	return 0;
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
			if (dwarf_tag(&scopes[i]) == DW_TAG_subprogram) {
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
		uint32_t pc_value = frame_state->registers[ARM_REG_PC];
		vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Failed to read memory at %x when unwinding with PC %x", *vsp, pc_value);
		return -1;
	}

	frame_state->registers[register_index] = register_value;
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
		*out_caller_value = frame_state->registers[register_index];
		return 0;
	}

	uint32_t expression_result;
	bool result_is_location;
	if (vc_dwarf_expression_evaluate(elf, ops, ops_count, dwarf_frame, frame_state, &expression_result, &result_is_location) < 0) {
		return -1;
	}

	if (result_is_location) {
		if (callbacks->memory_read(callbacks->user_data, expression_result, out_caller_value) < 0) {
			vc_elf_set_error(elf, VC_ELF_ERROR_NOT_FOUND, "Failed to read memory at %x when unwinding with PC %x", expression_result, frame_pc);
			return -1;
		}

		return 0;
	}

	*out_caller_value = expression_result;

	return 0;
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
		} else {
			out_caller_frame_state->registers[register_index] = caller_value;
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

static int vc_dwarf_expression_push(DwarfExpressionState *expression_state, uint32_t value) {
	if (expression_state->stack_position >= DWARF_EXPRESSION_MAX_STACK) {
		return -1;
	}

	expression_state->stack[expression_state->stack_position] = value;
	expression_state->stack_position++;

	return 0;
}

static int vc_dwarf_expression_pop(DwarfExpressionState *expression_state, uint32_t *out_value) {
	if (expression_state->stack_position == 0) {
		return -1;
	}

	expression_state->stack_position--;
	*out_value = expression_state->stack[expression_state->stack_position];

	return 0;
}

static int vc_dwarf_expression_evaluate(VcElf *elf, Dwarf_Op *ops, uint32_t ops_count, Dwarf_Frame *dwarf_frame, VcFrameState *frame_state,
                                   uint32_t *out_result, bool *out_is_location) {
	DwarfExpressionState expression_state = { 0 };
	Dwarf_Op *op = NULL;

	for (size_t op_index = 0; op_index < ops_count; op_index++) {
		op = &ops[op_index];

		switch (op->atom) {
		case DW_OP_plus_uconst: {
			uint32_t value;
			if (vc_dwarf_expression_pop(&expression_state, &value) < 0) goto bad_pop;

			value += op->number;

			if (vc_dwarf_expression_push(&expression_state, value) < 0) goto bad_push;
			break;
		}
		case DW_OP_regx: {
			if (op->number >= ARM_REG_COUNT) goto bad_register;

			uint32_t value = frame_state->registers[op->number];

			if (vc_dwarf_expression_push(&expression_state, value) < 0) goto bad_push;
			break;
		}
		case DW_OP_bregx: {
			if (op->number >= ARM_REG_COUNT) goto bad_register;

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

			uint32_t cfa;
			bool cfa_is_location;
			if (vc_dwarf_expression_evaluate(elf, cfa_ops, cfa_ops_count, NULL, frame_state, &cfa, &cfa_is_location) < 0) {
				return -1;
			}
			assert(cfa_is_location);

			if (vc_dwarf_expression_push(&expression_state, cfa) < 0) goto bad_push;
			break;
		}
		case DW_OP_stack_value: {
			if (vc_dwarf_expression_pop(&expression_state, out_result) < 0) goto bad_pop;
			*out_is_location = false;
			return 0;
		}
		default:
			vc_elf_set_error(elf, VC_ELF_ERROR_NOT_IMPLEMENTED, "Dwarf Op not implemented %x", op->atom);
			return -1;
		}
	}

	if (vc_dwarf_expression_pop(&expression_state, out_result) < 0) goto bad_pop;
	*out_is_location = true;

	return 0;

bad_register:
	vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Invalid ARM register %ld", op->number);
	return -1;

bad_push:
	vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Dwarf expression requires too much stack");
	return -1;

bad_pop:
	vc_elf_set_error(elf, VC_ELF_ERROR_INVALID_ELF, "Dwarf expression tried to pop an empty stack");
	return -1;
}
