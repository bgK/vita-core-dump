/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "vc_core.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gelf.h>
#include <libelf.h>
#include <zlib.h>

#define ERROR_MESSAGE_SIZE 2048

#define READ(data, type) \
	*(type *)data; \
	data += sizeof(type);

#define READ_U32(data) READ(data, uint32_t)

#define FREE(x) \
	free(x);    \
	x = NULL;

typedef struct CoreName {
	char s[32];
} CoreName;

typedef struct CoreModuleSegment {
	uint32_t unk_0;
	uint32_t attr;
	uint32_t start;
	uint32_t size;
	uint32_t align;
} CoreModuleSegment;

typedef struct CoreModule {
	uint32_t unk_0;
	uint32_t uid;
	uint32_t unk_8;
	uint32_t unk_12;
	uint32_t unk_16;
	uint32_t unk_20;
	uint32_t unk_24;
	uint32_t unk_28;
	uint32_t unk_32;
	CoreName name;
	uint32_t unk_68;
	uint32_t unk_72;
	uint32_t segment_count;
	CoreModuleSegment *segments;
	uint32_t unk_88;
	uint32_t unk_92;
	uint32_t unk_96;
	uint32_t unk_100;
} CoreModule;

typedef struct CoreThread {
	uint32_t structure_size;
	uint32_t uid;
	CoreName name;
	uint32_t unk_40;
	uint32_t unk_44;
	uint16_t status;
	uint16_t unk_50;
	uint32_t unk_52;
	uint32_t unk_56;
	uint32_t unk_60;
	uint32_t unk_64;
	uint32_t unk_68;
	uint32_t unk_72;
	uint32_t unk_76;
	uint32_t unk_80;
	uint32_t unk_84;
	uint32_t unk_88;
	uint32_t unk_92;
	uint32_t unk_96;
	uint32_t unk_100;
	uint32_t unk_104;
	uint32_t unk_108;
	uint32_t unk_112;
	uint32_t stop_reason;
	uint32_t unk_120;
	uint32_t unk_124;
	uint32_t unk_128;
	uint32_t unk_132;
	uint32_t unk_136;
	uint32_t unk_140;
	uint32_t unk_144;
	uint32_t unk_148;
	uint32_t unk_152;
	uint32_t pc;
	uint32_t unk_160;
	uint32_t unk_164;
	uint32_t unk_168;
	uint32_t unk_172;
	uint32_t unk_176;
	uint32_t unk_180;
	uint32_t unk_184;
	uint32_t unk_188;
	uint32_t unk_192;
	uint32_t unk_196;
} CoreThread;

typedef struct CoreThreadRegisters {
	uint32_t structure_size;
	uint32_t thread_id;
	uint32_t gpr[16];
	// TODO: More registers
} CoreThreadRegisters;

typedef struct MemoryArea {
	uint32_t offset;
	uint32_t address;
	uint32_t size;
} MemoryArea;

struct VcCore {
	bool loaded;
	char *filename;
	char *uncompressed_filename;

	int elf_fd;
	Elf *elf;

	uint32_t thread_count;
	CoreThread *threads;

	uint32_t thread_registers_count;
	CoreThreadRegisters *thread_registers;

	uint32_t module_count;
	CoreModule *modules;

	uint32_t mem_area_count;
	MemoryArea *mem_areas;

	int error_code;
	char error_message[ERROR_MESSAGE_SIZE];
};

static void vc_core_set_error(VcCore *core, int code, const char *message, ...) __attribute__ ((format (printf, 3, 4)));
static int vc_core_uncompress(VcCore *core);
static int vc_core_delete_uncompressed(VcCore *core);
static int vc_core_read_elf(VcCore *core);
static int vc_core_read_elf_note(VcCore *core, GElf_Phdr *phdr);
static int vc_core_close_elf(VcCore *core);
static int vc_core_read_module_info(VcCore *core, uint8_t *data, size_t data_size);
static int vc_core_read_thread_info(VcCore *core, uint8_t *data, size_t data_size);
static int vc_core_read_thread_reg_info(VcCore *core, uint8_t *data, size_t data_size);

int vc_core_get_error_code(VcCore *core) {
	return core->error_code;
}

const char *vc_core_get_error_message(VcCore *core) {
	return core->error_message;
}

static void vc_core_set_error(VcCore *core, int code, const char *message, ...) {
	va_list args;
	va_start(args, message);

	core->error_code = code;

	vsnprintf(core->error_message, ERROR_MESSAGE_SIZE, message, args);

	va_end(args);
}

VcCore *vc_core_new() {
	VcCore *core = calloc(1, sizeof(VcCore));
	if (!core) {
		return NULL;
	}

	core->elf_fd = -1;

	return core;
}

void vc_core_free(VcCore *core) {
	if (!core) {
		return;
	}

	vc_core_close_elf(core);
	vc_core_delete_uncompressed(core);

	for (uint32_t i = 0; i < core->module_count; i++) {
		FREE(core->modules[i].segments);
	}

	FREE(core->mem_areas);
	FREE(core->threads);
	FREE(core->thread_registers);
	FREE(core->modules);
	FREE(core->filename);
	FREE(core);
}

int vc_core_load(VcCore *core, const char *filename) {
	if (core->loaded) {
		vc_core_set_error(core, VC_CORE_ERROR_ALREADY_LOADED, "A core file is already loaded");
		goto error;
	}

	core->filename = strdup(filename);

	if (vc_core_uncompress(core) < 0) {
		goto error;
	}

	if (vc_core_read_elf(core) < 0) {
		goto error;
	}

	core->loaded = true;

	return 0;

error:
	vc_core_close_elf(core);
	vc_core_delete_uncompressed(core);
	FREE(core->filename);

	return -1;
}

static int vc_core_uncompress(VcCore *core) {
	FILE *uncompressed_core_dump = NULL;

	gzFile compressed_core_dump = gzopen(core->filename, "rb");
	if (!compressed_core_dump) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_OPEN_FAILED, "%s", strerror(errno));
		goto error;
	}

	// Larger buffer size for better performance
	gzbuffer(compressed_core_dump, 128 * 1024);

	char uncompressed_core_dump_file_name[1024];
	snprintf(uncompressed_core_dump_file_name, 1024, "uncompressed-core-dump-XXXXXX");
	int uncompressed_core_dump_fd = mkstemp(uncompressed_core_dump_file_name);
	if (uncompressed_core_dump_fd < 0) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Failed to create uncompressed core dump temporary file %s: %s", uncompressed_core_dump_file_name, strerror(errno));
		goto error;
	}

	core->uncompressed_filename = strdup(uncompressed_core_dump_file_name);

	uncompressed_core_dump = fdopen(uncompressed_core_dump_fd, "wb");
	if (!uncompressed_core_dump) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Failed to open uncompressed core dump temporary file %s: %s", core->uncompressed_filename, strerror(errno));
		goto error;
	}

	while (1) {
		uint8_t buffer[8192];

		int read = gzread(compressed_core_dump, buffer, 8192);
		if (read <= 0) {
			int gz_error_code = 0;
			const char *error_message = gzerror(compressed_core_dump, &gz_error_code);
			if (gz_error_code == Z_OK) {
				break; // End of input
			}

			vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Failed to read as a gzip stream: %s", error_message);
			goto error;
		}

		fwrite(buffer, read, 1, uncompressed_core_dump);

		if (ferror(uncompressed_core_dump)) {
			vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Failed to write to the uncompressed core dump temporary file %s: %s", core->uncompressed_filename, strerror(errno));
			goto error;
		}
	}

	fclose(uncompressed_core_dump);
	uncompressed_core_dump = NULL;

	int close_result = gzclose(compressed_core_dump);
	if (close_result != Z_OK) {
		const char *error_message = NULL;
		if (close_result == Z_ERRNO) {
			error_message = strerror(errno);
		} else if (close_result == Z_STREAM_ERROR) {
			error_message = "Invalid gzip file";
		} else if (close_result == Z_BUF_ERROR) {
			error_message = "Truncated gzip file";
		} else {
			error_message = "Unknown error";
		}

		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "%s", error_message);
		goto error;
	}

	return 0;

error:
	if (uncompressed_core_dump) {
		fclose(uncompressed_core_dump);
	}

	if (compressed_core_dump) {
		gzclose(compressed_core_dump);
	}

	vc_core_delete_uncompressed(core);

	return -1;
}

static int vc_core_delete_uncompressed(VcCore *core) {
	if (!core->uncompressed_filename) {
		return 0;
	}

	unlink(core->uncompressed_filename);

	FREE(core->uncompressed_filename);

	return 0;
}

static int compare_mem_areas(const void *p1, const void *p2) {
	const MemoryArea *area1 = p1;
	const MemoryArea *area2 = p2;
	return area1->address > area2->address;
}

static int vc_core_read_elf(VcCore *core) {
	elf_version(EV_CURRENT);

	core->elf_fd = open(core->uncompressed_filename, O_RDONLY);

	core->elf = elf_begin(core->elf_fd, ELF_C_READ, NULL);
	if (!core->elf) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Failed to open as an elf file: %s", elf_errmsg(-1));
		goto error;
	}

	GElf_Ehdr ehdr_mem;
	GElf_Ehdr *ehdr = gelf_getehdr(core->elf, &ehdr_mem);
	if (!ehdr) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Failed to get the elf file header: %s", elf_errmsg(-1));
		goto error;
	}

	if (ehdr->e_type != ET_CORE) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "The file is not a core dump");
		goto error;
	}

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32 || ehdr->e_ident[EI_DATA] != ELFDATA2LSB || ehdr->e_machine != EM_ARM) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "The elf is not for the 32-bit LE ARM architecture");
		goto error;
	}

	size_t phdr_count;
	if (elf_getphdrnum(core->elf, &phdr_count) == -1) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Failed to get the program header count: %s", elf_errmsg(-1));
		goto error;
	}

	core->mem_area_count = 0;

	for (size_t phdridx = 0; phdridx < phdr_count; phdridx++) {
		GElf_Phdr mem;
		GElf_Phdr *phdr = gelf_getphdr(core->elf, phdridx, &mem);
		if (!phdr) {
			vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Failed to get program header %lu: %s", phdridx, elf_errmsg(-1));
			goto error;
		}

		switch (phdr->p_type) {
		case PT_NOTE:
			if (vc_core_read_elf_note(core, phdr) < 0) {
				goto error;
			}
			break;
		case PT_LOAD:
			core->mem_area_count++;
			break;
		default: // Unhandled type
			assert(false);
			break;
		}
	}

	if (core->mem_area_count) {
		core->mem_areas = calloc(core->mem_area_count, sizeof(MemoryArea));

		uint32_t area_index = 0;
		for (size_t phdridx = 0; phdridx < phdr_count; phdridx++) {
			GElf_Phdr mem;
			GElf_Phdr *phdr = gelf_getphdr(core->elf, phdridx, &mem);
			if (!phdr) {
				vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Failed to get program header %lu: %s", phdridx, elf_errmsg(-1));
				goto error;
			}

			if (phdr->p_type == PT_LOAD) {
				MemoryArea *area = &core->mem_areas[area_index];
				area->offset  = phdr->p_offset;
				area->address = phdr->p_vaddr;
				area->size    = phdr->p_filesz;

				area_index++;
			}
		}

		assert(area_index == core->mem_area_count);

		qsort(core->mem_areas, core->mem_area_count, sizeof(MemoryArea), &compare_mem_areas);
	}

	return 0;

error:
	core->mem_area_count = 0;
	vc_core_close_elf(core);

	return -1;
}

static int vc_core_close_elf(VcCore *core) {
	if (core->elf) {
		elf_end(core->elf);
		core->elf = NULL;
	}

	if (core->elf_fd >= 0) {
		close(core->elf_fd);
		core->elf_fd = -1;
	}

	return 0;
}

static int vc_core_read_elf_note(VcCore *core, GElf_Phdr *phdr) {
	assert(phdr->p_type == PT_NOTE);

	Elf_Data *note_data = elf_getdata_rawchunk(core->elf, phdr->p_offset, phdr->p_filesz, (phdr->p_align == 8 ? ELF_T_NHDR8 : ELF_T_NHDR));
	if (!note_data) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Unable to get note data pointer: %s", elf_errmsg(-1));
		return -1;
	}

	GElf_Nhdr nhdr;
	size_t name_offset;
	size_t desc_offset;
	if (gelf_getnote(note_data, 0, &nhdr, &name_offset, &desc_offset) <= 0) {
		vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Unable to read note header: %s", elf_errmsg(-1));
		return -1;
	}

	const char *name = nhdr.n_namesz == 0 ? "" : note_data->d_buf + name_offset;

	if (strncmp(name, "MODULE_INFO", nhdr.n_namesz) == 0) {
		if (vc_core_read_module_info(core, note_data->d_buf + desc_offset, nhdr.n_descsz) < 0) {
			return -1;
		}
	} else if (strncmp(name, "THREAD_INFO", nhdr.n_namesz) == 0) {
		if (vc_core_read_thread_info(core, note_data->d_buf + desc_offset, nhdr.n_descsz) < 0) {
			return -1;
		}
	} else if (strncmp(name, "THREAD_REG_INFO", nhdr.n_namesz) == 0) {
		if (vc_core_read_thread_reg_info(core, note_data->d_buf + desc_offset, nhdr.n_descsz) < 0) {
			return -1;
		}
	}

	return 0;
}

static int vc_core_ensure_space(uint8_t *position, uint8_t *end, uint32_t needed) {
	int remaining = end - position;
	if (remaining < 0) {
		return -1;
	}

	if ((uintptr_t) remaining < needed) {
		return -1;
	}

	return 0;
}

static int vc_core_read_module_info(VcCore *core, uint8_t *data, size_t data_size) {
	assert(!core->modules);

	uint8_t *end = data + data_size;

	if (data_size < 8) {
		goto invalid;
	}

	uint32_t unk = READ_U32(data);
	(void)unk;
	assert(unk == 1);

	core->module_count = READ_U32(data);
	core->modules = calloc(core->module_count, sizeof(CoreModule));

	for (uint32_t module_index = 0; module_index < core->module_count; module_index++) {
		if (vc_core_ensure_space(data, end, sizeof(CoreModule) - sizeof(CoreModuleSegment *)) < 0) {
			goto invalid;
		}

		CoreModule *module = &core->modules[module_index];
		module->unk_0         = READ_U32(data);
		module->uid           = READ_U32(data);
		module->unk_8         = READ_U32(data);
		module->unk_12        = READ_U32(data);
		module->unk_16        = READ_U32(data);
		module->unk_20        = READ_U32(data);
		module->unk_24        = READ_U32(data);
		module->unk_28        = READ_U32(data);
		module->unk_32        = READ_U32(data);
		module->name          = READ(data, CoreName);
		module->unk_68        = READ_U32(data);
		module->unk_72        = READ_U32(data);
		module->segment_count = READ_U32(data);

		module->segments = calloc(module->segment_count, sizeof(CoreModuleSegment));

		for (uint32_t segment_index = 0; segment_index < module->segment_count; segment_index++) {
			if (vc_core_ensure_space(data, end, sizeof(CoreModuleSegment)) < 0) {
				goto invalid;
			}

			CoreModuleSegment *segment = &module->segments[segment_index];
			*segment = READ(data, CoreModuleSegment);
		}

		if (vc_core_ensure_space(data, end, sizeof(uint32_t) * 4) < 0) {
			goto invalid;
		}

		module->unk_88        = READ_U32(data);
		module->unk_92        = READ_U32(data);
		module->unk_96        = READ_U32(data);
		module->unk_100       = READ_U32(data);
	}

	return 0;

invalid:
	for (uint32_t i = 0; i < core->module_count; i++) {
		FREE(core->modules[i].segments);
	}
	FREE(core->modules);
	core->module_count = 0;

	vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Invalid MODULE_INFO");
	return -1;
}

static int vc_core_read_thread_info(VcCore *core, uint8_t *data, size_t data_size) {
	assert(!core->threads);

	uint8_t *end = data + data_size;

	if (data_size < 8) {
		goto invalid;
	}

	uint32_t unk = READ_U32(data);
	(void)unk;
	assert(unk == 18);

	core->thread_count = READ_U32(data);
	if (vc_core_ensure_space(data, end, sizeof(CoreThread) * core->thread_count) < 0) {
		goto invalid;
	}

	core->threads = calloc(core->thread_count, sizeof(CoreThread));

	for (uint32_t thread_index = 0; thread_index < core->thread_count; thread_index++) {
		uint8_t *thread_start = data;

		CoreThread *thread = &core->threads[thread_index];
		*thread = READ(data, CoreThread);
		assert(thread->structure_size == 200);

		data = thread_start + thread->structure_size;
	}

	return 0;

invalid:
	FREE(core->threads);
	core->thread_count = 0;

	vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Invalid THREAD_INFO");
	return -1;
}

static int vc_core_read_thread_reg_info(VcCore *core, uint8_t *data, size_t data_size) {
	assert(!core->thread_registers);

	uint8_t *end = data + data_size;

	if (data_size < 8) {
		goto invalid;
	}

	uint32_t unk = READ_U32(data);
	(void)unk;
	assert(unk == 17);

	core->thread_registers_count = READ_U32(data);
	core->thread_registers = calloc(core->thread_registers_count, sizeof(CoreThreadRegisters));

	for (uint32_t thread_index = 0; thread_index < core->thread_registers_count; thread_index++) {
		if (vc_core_ensure_space(data, end, sizeof(CoreThreadRegisters)) < 0) {
			goto invalid;
		}

		uint8_t *thread_start = data;

		CoreThreadRegisters *thread = &core->thread_registers[thread_index];
		*thread = READ(data, CoreThreadRegisters);
		assert(thread->structure_size == 376);

		data = thread_start + thread->structure_size;
	}

	return 0;

invalid:
	FREE(core->thread_registers);
	core->thread_registers_count = 0;

	vc_core_set_error(core, VC_CORE_ERROR_CORE_INVALID_DUMP, "Invalid THREAD_REG_INFO");
	return -1;
}

static int vc_core_find_memory_area(VcCore *core, uint32_t address, MemoryArea **out_area) {
	if (!core->loaded) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_LOADED, "No core dump loaded");
		return -1;
	}

	if (!core->mem_areas) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_FOUND, "No areas in core dump");
		return -1;
	}

	// TODO: Binary search
	for (uint32_t i = 0; i < core->mem_area_count; i++) {
		MemoryArea *area = &core->mem_areas[i];
		if (address >= area->address && address < (area->address + area->size)) {
			*out_area = area;
			return 0;
		}
	}

	vc_core_set_error(core, VC_CORE_ERROR_NOT_FOUND, "Memory area not found");
	return -1;
}

int vc_core_get_module_count(VcCore *core, uint32_t *out_count) {
	if (!core->loaded) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_LOADED, "No core dump loaded");
		return -1;
	}

	*out_count = core->module_count;

	return 0;
}

int vc_core_get_module(VcCore *core, uint32_t module_index, VcModule *out_module) {
	if (!core->loaded) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_LOADED, "No core dump loaded");
		return -1;
	}

	if (module_index >= core->module_count) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_FOUND, "No module with index %d", module_index);
		return -1;
	}

	CoreModule *module = &core->modules[module_index];

	uint32_t load_address = 0;
	uint32_t end_address = 0;

	if (module->segment_count) {
		load_address = module->segments[0].start;
	}

	for (uint32_t i = 0; i < module->segment_count; i++) {
		CoreModuleSegment *segment = &module->segments[i];
		uint32_t segment_end_address = segment->start + segment->size;
		if (segment->start >= load_address && segment_end_address > end_address) {
			end_address = segment_end_address;
		}
	}

	assert(end_address != 0);

	strncpy(out_module->name, module->name.s, sizeof(out_module->name));
	out_module->load_address = load_address;
	out_module->size = end_address - load_address;

	return 0;
}

int vc_core_get_thread(VcCore *core, uint32_t index, VcThread *out_thread) {
	if (!core->loaded) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_LOADED, "No core dump loaded");
		return -1;
	}

	if (index >= core->thread_count) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_FOUND, "No thread with index %d", index);
		return -1;
	}

	CoreThread *thread = &core->threads[index];

	CoreThreadRegisters *registers = NULL;
	for (uint32_t i = 0; i < core->thread_registers_count; i++) {
		if (core->thread_registers[i].thread_id == thread->uid) {
			registers = &core->thread_registers[i];
		}
	}

	if (!registers) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_FOUND, "No registers information for thread with index %d", index);
		return -1;
	}

	strncpy(out_thread->name, thread->name.s, sizeof(out_thread->name));
	out_thread->status      = thread->status;
	out_thread->stop_reason = thread->stop_reason;
	memcpy(out_thread->registers, registers->gpr, sizeof(registers->gpr));

	return 0;
}

int vc_core_get_thread_count(VcCore *core, uint32_t *out_count) {
	if (!core->loaded) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_LOADED, "No core dump loaded");
		return -1;
	}

	*out_count = core->thread_count;

	return 0;
}

int vc_core_memory_read(VcCore *core, uint32_t address, uint32_t *out_result) {
	if (!core->loaded) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_LOADED, "No core dump loaded");
		return -1;
	}

	MemoryArea *area;
	if (vc_core_find_memory_area(core, address, &area) < 0) {
		return -1;
	}

	Elf_Data *raw_data = elf_getdata_rawchunk(core->elf, area->offset, area->size, ELF_T_BYTE);
	if (!raw_data) {
		vc_core_set_error(core, VC_CORE_ERROR_NOT_FOUND, "Unable to get area data pointer: %s", elf_errmsg(-1));
		return -1;
	}

	assert(raw_data->d_size == area->size);

	*out_result = *(uint32_t *)(raw_data->d_buf + address - area->address);

	return 0;
}

const char *vc_core_get_thread_status_name(uint32_t thread_status) {
	switch (thread_status) {
	case 1:   return "Running";
	case 2:   return "Ready";
	case 4:   return "Standby";
	case 8:   return "Waiting";
	case 16:  return "Dormant";
	case 32:  return "Dead";
	case 64:  return "Deleted";
	case 128: return "Stagnant";
	case 256: return "Suspended";
	default:  return NULL;
	}
}

const char *vc_core_get_thread_stop_reason_name(uint32_t stop_reason) {
	switch (stop_reason) {
	case 0x30002: return "Undefined instruction exception";
	case 0x30003: return "Prefetch abort exception";
	case 0x30004: return "Data abort exception";
	case 0x60080: return "Division by zero";
	default:  return NULL;
	}
}
