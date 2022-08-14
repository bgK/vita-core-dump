/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "vc_address_space.h"
#include "vc_core.h"
#include "vc_elf.h"

#include <assert.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VC_VERSION "1.3"

enum {
	COMMAND_BACKTRACE,
	COMMAND_HELP,
	COMMAND_MEMORY,
	COMMAND_MODULES,
	COMMAND_STACK,
	COMMAND_THREADS,
};

enum {
	THREAD_INDEX_CRASHED = -1,
	THREAD_INDEX_ALL     = -2,
};

// from libstdc++
char *__cxa_demangle(const char *mangled_name, char *output_buffer, size_t *length, int *status);

static int memory_read_callback(void *user_data, uint32_t address, uint32_t *out_result) {
	VcCore *core = user_data;
	return vc_core_memory_read_u32(core, address, out_result);
}

static void print_usage() {
	printf("vita-core-dump version " VC_VERSION "\n");
	printf("\n");
	printf("usage: vita-core-dump <core-dump-path> <command> [<arguments>]\n");
	printf("\n");
	printf("The commands are:\n");
	printf("   backtrace    Print a backtrace for one or more threads\n");
	printf("   modules      Print the list of loaded modules\n");
	printf("   stack        Print the stack for one or more threads\n");
	printf("   threads      Print the list of threads\n");
	printf("   memory       Display data from the process's memory\n");
	printf("\n");
	printf("See vita-core-dump help <command> to read more about a command.\n");
}

static int parse_command(const char *command) {
	if (strcasecmp(command, "backtrace") == 0 || strcasecmp(command, "bt") == 0) {
		return COMMAND_BACKTRACE;
	} else if (strcasecmp(command, "help") == 0) {
		return COMMAND_HELP;
	} else if (strcasecmp(command, "memory") == 0) {
		return COMMAND_MEMORY;
	} else if (strcasecmp(command, "modules") == 0) {
		return COMMAND_MODULES;
	} else if (strcasecmp(command, "threads") == 0) {
		return COMMAND_THREADS;
	} else if (strcasecmp(command, "stack") == 0) {
		return COMMAND_STACK;
	}

	return -1;
}

static void print_thread_summary(uint32_t thread_index, VcThread *thread) {
	printf("Thread %d:", thread_index);
	if (strlen(thread->name) != 0) {
		printf(" %s", thread->name);
	}

	const char *thread_status_name = vc_core_get_thread_status_name(thread->status);
	if (thread_status_name) {
		printf(" (%s)", thread_status_name);
	} else {
		printf(" (%x)", thread->status);
	}

	if (thread->stop_reason) {
		const char *stop_reason_name = vc_core_get_thread_stop_reason_name(thread->stop_reason);
		if (stop_reason_name) {
			printf(" - %s", stop_reason_name);
		} else {
			printf(" - Stop reason 0x%x", thread->stop_reason);
		}
	}

	printf(" at PC 0x%08x", thread->registers[ARM_REG_PC]);

	if (thread->stop_reason == VcStopReasonDataAbortException) {
		bool wnr = (thread->dfsr >> ARM_DFSR_WNR) & 1;
		printf(" %s memory at 0x%08x", wnr ? "writing" : "reading", thread->dfar);
	}

	printf("\n");
}

static void print_registers(uint32_t *registers, uint16_t registers_with_unknown_value) {
	printf("   ");
	for (uint32_t register_index = 0; register_index < ARM_REG_COUNT; register_index++) {
		if (register_index != 0 && (register_index % 4) == 0) {
			printf("\n   ");
		}
		char register_name[4];
		if (register_index == ARM_REG_SP) {
			strncpy(register_name, "sp", 4);
		} else if (register_index == ARM_REG_LR) {
			strncpy(register_name, "lr", 4);
		} else if (register_index == ARM_REG_PC) {
			strncpy(register_name, "pc", 4);
		} else {
			snprintf(register_name, 4, "r%d", register_index);
		}

		if (registers_with_unknown_value & (1 << register_index)) {
			printf(" %3s: unknown   ", register_name);
		} else {
			printf(" %3s: 0x%08x", register_name, registers[register_index]);
		}
	}
	printf("\n");
}

static void print_hex_dump(const uint8_t *data, int length, int bytes_per_line, int start_address, int indentation) {
	assert(1 <= bytes_per_line && bytes_per_line <= 32);
	int offset = start_address;
	while (length >= bytes_per_line) {
		for (int i = 0; i < indentation; i++) {
			printf(" ");
		}
		printf("%08x: ", offset);
		for (int i = 0; i < bytes_per_line; i++) {
			printf("%02x ", data[i]);
			if (i % 4 == 3) {
				printf(" ");
			}
		}
		printf(" |");
		for (int i = 0; i < bytes_per_line; i++) {
			uint8_t c = data[i];
			if (c < 32 || c >= 127) {
				c = '.';
			}
			printf("%c", c);
		}
		printf("|\n");
		data   += bytes_per_line;
		length -= bytes_per_line;
		offset += bytes_per_line;
	}

	if (length <= 0) {
		return;
	}

	for (int i = 0; i < indentation; i++) {
		printf(" ");
	}
	printf("%08x: ", offset);
	for (int i = 0; i < bytes_per_line; i++) {
		if (i < length) {
			printf("%02x ", data[i]);
		} else {
			printf("   ");
		}
		if (i % 4 == 3) {
			printf(" ");
		}
	}
	printf(" |");
	int i = 0;
	for (; i < length; i++) {
		uint8_t c = data[i];
		if (c < 32 || c >= 127) {
			c = '.';
		}
		printf("%c", c);
	}
	for (; i < bytes_per_line; i++) {
		printf(" ");
	}
	printf("|\n");
}

static int print_variable(VcCore *core, VcVariableInfo *variable) {
	if (variable->size == 0) {
		assert(false);
		variable->size = 4;
	}

	uint8_t *data;
	uint32_t address = 0;
	if (variable->location_type == VcVariableLocationTypeMemory) {
		uint32_t bytes_read;
		if (vc_core_memory_read(core, variable->location, variable->size, &data, &bytes_read) < 0) {
			printf("    %15s: Data missing in core dump\n", variable->name);
			return -1;
		}
		address = variable->location;
	} else if (variable->location_type == VcVariableLocationTypeValue) {
		data = (uint8_t *)&variable->location;
	} else if (variable->location_type == VcVariableLocationTypeError) {
		printf("    %15s: %s\n", variable->name, variable->error_message);
		return -1;
	} else {
		assert(false);
	}

	switch (variable->type) {
	case VcVariableTypeInteger:
		if (variable->size == 1) {
			printf("    %15s: 0x%02x\n", variable->name, *(uint8_t *)data);
		} else if (variable->size == 2) {
			printf("    %15s: 0x%04x\n", variable->name, *(uint16_t *)data);
		} else if (variable->size == 4) {
			printf("    %15s: 0x%08x\n", variable->name, *(uint32_t *)data);
		} else if (variable->size == 8) {
			printf("    %15s: 0x%016lx\n", variable->name, *(uint64_t *)data);
		} else {
			printf("    %15s:\n", variable->name);
			print_hex_dump(data, variable->size, 16, address, 15);
		}
		break;
	case VcVariableTypeFloat:
		if (variable->size == 4) {
			printf("    %15s: %f\n", variable->name, *(float *)data);
		} else if (variable->size == 8) {
			printf("    %15s: %f\n", variable->name, *(double *)data);
		} else {
			printf("    %15s:\n", variable->name);
			print_hex_dump(data, variable->size, 16, address, 15);
		}
		break;
	case VcVariableTypeUnhandled:
		printf("    %15s:\n", variable->name);
		print_hex_dump(data, variable->size, 16, address, 15);
		break;
	}

	return 0;
}

static int print_backtrace_for_thread(VcCore *core, VcAddressSpace *address_space, VcThread *thread, bool show_locals, bool show_registers) {
	VcFrameState frame_state;
	memcpy(frame_state.registers, thread->registers, sizeof(frame_state.registers));
	frame_state.registers_with_unknown_value = 0;

	uint32_t frame_number = 0;

	while (1) {
		frame_number++;
		if (frame_number > 500) {
			fprintf(stderr, "Too many frames to unwind, aborting\n");
			goto error;
		}

		uint32_t pc = frame_state.registers[ARM_REG_PC];

		VcAddressSpaceModule *module;
		if (vc_address_space_find_module_by_address(address_space, pc, &module) < 0) {
			printf("  0x%08x %16s: ??\n", pc, "");

			if (show_registers) {
				print_registers(frame_state.registers, frame_state.registers_with_unknown_value);
			}

			// Maybe we branched with link into a bad address, try unwinding from LR
			if (frame_number == 1 && thread->stop_reason == VcStopReasonPrefetchAbortException && thread->registers[ARM_REG_PC] == thread->ifar) {
				frame_state.registers[ARM_REG_PC] = frame_state.registers[ARM_REG_LR];
				continue;
			}

			fprintf(stderr, "Unable to unwind: No module for PC 0x%x\n", pc);
			goto error;
		}

		char pretty_module[32];
		snprintf(pretty_module, 32, "(%s)", module->name);

		if (!module->elf) {
			printf("  0x%08x %16s: ??\n", pc, pretty_module);

			if (show_registers) {
				print_registers(frame_state.registers, frame_state.registers_with_unknown_value);
			}

			fprintf(stderr, "Unable to unwind: No binary for module '%s'\n", module->name);
			goto error;
		}

		uint32_t elf_base_address;
		if (vc_elf_get_base_address(module->elf, &elf_base_address) < 0) {
			fprintf(stderr, "Failed to get elf base address: %s\n", vc_elf_get_error_message(module->elf));
			goto error;
		}

		// Translate run-time PC to executable virtual address
		// NOTE: The proper way to do this is probably to relocate the executable
		uint32_t elf_va_pc = pc - module->load_address + elf_base_address;
		frame_state.registers[ARM_REG_PC] = elf_va_pc;

		VcAddressInfo pc_info;
		if (vc_elf_get_pc_info(module->elf, elf_va_pc, &pc_info) >= 0) {
			int demangle_status;
			char *demangled_name = __cxa_demangle(pc_info.function_name, 0, 0, &demangle_status);
			const char *display_name = demangle_status >= 0 ? demangled_name : pc_info.function_name;

			if (pc_info.line_filename) {
				printf("  0x%08x %16s: in %s+0x%x at %s:%d\n", elf_va_pc, pretty_module, display_name, pc_info.function_offset, pc_info.line_filename, pc_info.line_number);
			} else {
				printf("  0x%08x %16s: in %s+0x%x\n", elf_va_pc, pretty_module, display_name, pc_info.function_offset);
			}

			free(demangled_name);
		} else {
			printf("  0x%08x %16s: ??\n", elf_va_pc, pretty_module);
		}

		if (show_registers) {
			print_registers(frame_state.registers, frame_state.registers_with_unknown_value);
		}

		VcUnwindCallbacks callbacks = {
		    .user_data   = core,
		    .memory_read = &memory_read_callback
		};

		VcFrameState caller_frame_state;
		int unwind_result = vc_elf_unwind_one_frame(module->elf, &callbacks, &frame_state, &caller_frame_state);
		char unwind_error_message[VC_ELF_ERROR_MESSAGE_SIZE];
		if (unwind_result < 0) {
			strncpy(unwind_error_message, vc_elf_get_error_message(module->elf), VC_ELF_ERROR_MESSAGE_SIZE);
			unwind_error_message[VC_ELF_ERROR_MESSAGE_SIZE - 1] = '\0';
		}

		if (show_locals) {
			VcFrameState *caller_frame_state_ptr = unwind_result >= 0 ? &caller_frame_state : NULL;

			VcVariableInfo *local_variables;
			uint32_t local_variable_count;
			if (vc_elf_get_local_variables_at_pc(module->elf, elf_va_pc, caller_frame_state_ptr, &frame_state, &local_variables, &local_variable_count) >= 0) {
				for (uint32_t variable_index = 0; variable_index < local_variable_count; variable_index++) {
					VcVariableInfo *local_variable = &local_variables[variable_index];
					print_variable(core, local_variable);
				}
				free(local_variables);
			}
		}

		if (unwind_result < 0) {
			fprintf(stderr, "Failed to unwind: %s\n", unwind_error_message);
			goto error;
		}

		memcpy(&frame_state, &caller_frame_state, sizeof(VcFrameState));
	}

	return 0;

error:
	return -1;
}

static int print_stack_for_thread(VcCore *core, VcAddressSpace *address_space, VcThread *thread, uint32_t stack_length) {

	uint32_t sp = thread->registers[ARM_REG_SP];
	uint32_t start_address = sp - 5            * sizeof(uint32_t);
	uint32_t end_address   = sp + stack_length * sizeof(uint32_t);

	for (uint32_t stack_address = start_address; stack_address < end_address; stack_address += sizeof(uint32_t)) {
		uint32_t stack_value;
		if (vc_core_memory_read_u32(core, stack_address, &stack_value) < 0) {
			fprintf(stderr, "Unable to read memory from core dump at address %x: %s\n", stack_address, vc_core_get_error_message(core));
			return -1;
		}

		char stack_value_info[1024];
		memset(stack_value_info, 0, 1024);

		VcAddressSpaceModule *module = NULL;
		vc_address_space_find_module_by_address(address_space, stack_value, &module);

		if (module && module->elf) {
			uint32_t elf_base_address = 0;
			vc_elf_get_base_address(module->elf, &elf_base_address);

			uint32_t elf_va = stack_value - module->load_address + elf_base_address;

			VcAddressInfo pc_info;
			if (vc_elf_get_pc_info(module->elf, elf_va, &pc_info) >= 0) {
				int demangle_status;
				char *demangled_name = __cxa_demangle(pc_info.function_name, 0, 0, &demangle_status);
				const char *display_name = demangle_status >= 0 ? demangled_name : pc_info.function_name;

				if (pc_info.line_filename) {
					snprintf(stack_value_info, 1024, "%s in %s+0x%x at %s:%d", module->name, display_name, pc_info.function_offset, pc_info.line_filename, pc_info.line_number);
				} else {
					snprintf(stack_value_info, 1024, "%s in %s+0x%x", module->name, display_name, pc_info.function_offset);
				}

				free(demangled_name);
			} else {
				snprintf(stack_value_info, 1024, "%s+0x%x", module->name, elf_va);
			}
		}

		if (module && *stack_value_info == '\0') {
			snprintf(stack_value_info, 1024, "%s+0x%x", module->name, stack_value - module->load_address);
		}

		printf("  %s 0x%08x: 0x%08x  %s\n", stack_address == sp ? "SP>" : "   ", stack_address, stack_value, stack_value_info);
	}

	return 0;
}

static int handle_argument_thread(char *argument, int *out_thread_index) {
	if (strcasecmp(argument, "crashed") == 0) {
		*out_thread_index = THREAD_INDEX_CRASHED;
	} else if (strcasecmp(argument, "all") == 0) {
		*out_thread_index = THREAD_INDEX_ALL;
	} else {
		char *end;
		*out_thread_index = strtol(argument, &end, 10);
		if (*argument == '\0' || *end != '\0' || *out_thread_index < 0) {
			fprintf(stderr, "Invalid --thread argument '%s'\n", argument);
			return -1;
		}
	}

	return 0;
}

static int handle_argument_add_elf(char *argument, VcAddressSpace *address_space) {
	VcElf *elf = vc_elf_new();

	if (*argument == '\0') {
		fprintf(stderr, "Invalid --add-elf argument '%s'. Expected '<path-to-elf>[:<hex-load-address>]'\n", argument);
		goto error;
	}

	char *file_path;
	uint32_t load_address;
	VcAddressSpaceModule *matching_module = NULL;

	char *address_part = strchr(argument, ':');
	if (!address_part) {
		file_path = argument;

		if (vc_elf_load(elf, file_path) < 0) {
			fprintf(stderr, "Failed to load elf file '%s': %s\n", file_path, vc_elf_get_error_message(elf));
			goto error;
		}

		const char *module_name;
		if (vc_elf_get_module_name(elf, &module_name) < 0) {
			fprintf(stderr, "Failed to get elf module name for '%s': %s\n", file_path, vc_elf_get_error_message(elf));
			goto error;
		}

		char *allocated_module_name = NULL;
		if (!module_name) {
			// Default to the base name of the elf file without extension
			allocated_module_name = strdup(basename(argument));
			char *extension_dot = strchr(allocated_module_name, '.');
			if (extension_dot && extension_dot != allocated_module_name) *extension_dot = '\0';

			module_name = allocated_module_name;
		}

		if (vc_address_space_find_module_by_name(address_space, module_name, &matching_module) < 0) {
			fprintf(stderr, "Could not find a core dump module named '%s'. Ensure you are loading a SCE elf, or that the elf file name matches the desired module, or specify a load address if this is a dynamically loaded binary.\n", module_name);
			free(allocated_module_name);
			goto error;
		}

		load_address = matching_module->load_address;

		free(allocated_module_name);
	} else {
		if (address_part == argument || address_part[1] == '\0') {
			fprintf(stderr, "Invalid --add-elf argument '%s'. Expected '<path-to-elf>[:<hex-load-address>]'\n", argument);
			goto error;
		}

		*address_part = '\0';
		address_part++;

		char *end;
		load_address = strtoul(address_part, &end, 16);
		if (*end != '\0') {
			fprintf(stderr, "Invalid --add-elf load address '%s'\n", address_part);
			goto error;
		}

		file_path = argument;

		if (vc_elf_load(elf, file_path) < 0) {
			fprintf(stderr, "Failed to load elf file '%s': %s\n", file_path, vc_elf_get_error_message(elf));
			goto error;
		}
	}

	if (!matching_module) {
		uint32_t elf_size;
		if (vc_elf_get_memory_size(elf, &elf_size) < 0) {
			fprintf(stderr, "Failed to get elf memory size for '%s': %s\n", file_path, vc_elf_get_error_message(elf));
			goto error;
		}

		matching_module = vc_address_space_add_module(address_space, basename(file_path), load_address, elf_size);
	}

	matching_module->elf = elf;

	return 0;

error:
	vc_elf_free(elf);

	return -1;
}

static int handle_command_backtrace(VcCore *core, int argc, const char **argv) {
	static struct option long_options[] = {
		{ "add-elf",        required_argument, 0,  0 },
		{ "show-locals",    no_argument,       0,  0 },
		{ "show-registers", no_argument,       0,  0 },
		{ "thread",         required_argument, 0,  0 },
		{ 0,                0,                 0,  0 }
	};

	VcAddressSpace *address_space = vc_address_space_new();
	if (vc_address_space_add_modules_from_core(address_space, core) < 0) {
		fprintf(stderr, "%s\n", vc_address_space_get_error_message(address_space));
		goto error;
	}

	int selected_thread = THREAD_INDEX_CRASHED;
	bool show_locals    = false;
	bool show_registers = false;

	optind = 3; // Two arguments were already consumed

	while (1) {
		int long_option_index;
		int opt = getopt_long(argc, (char *const *)argv, "", long_options, &long_option_index);
		if (opt == -1) {
			break; // done parsing
		} else if (opt == '?') {
			goto error; // error
		} else if (opt == 0) {
			// long option
			switch (long_option_index) {
			case 0: // --add-elf
				if (handle_argument_add_elf(optarg, address_space) < 0) {
					goto error;
				}
				break;
			case 1: // --show-locals
				show_locals = true;
				break;
			case 2: // --show-registers
				show_registers = true;
				break;
			case 3: // --thread
				if (handle_argument_thread(optarg, &selected_thread) < 0) {
					goto error;
				}
				break;
			}
		}
	}

	uint32_t thread_count;
	if (vc_core_get_thread_count(core, &thread_count) < 0) {
		fprintf(stderr, "Failed to get thread count: %s\n", vc_core_get_error_message(core));
		goto error;
	}

	if (selected_thread >= (int)thread_count) {
		fprintf(stderr, "Invalid --thread argument '%d': there are %d threads\n", selected_thread, thread_count);
		goto error;
	}

	bool printed_thread_already = false;
	for (uint32_t thread_index = 0; thread_index < thread_count; thread_index++) {
		VcThread thread;
		if (vc_core_get_thread(core, thread_index, &thread) < 0) {
			fprintf(stderr, "Failed to get thread %d: %s\n", thread_index, vc_core_get_error_message(core));
			goto error;
		}

		bool do_thread = (selected_thread == THREAD_INDEX_ALL)
		        || (selected_thread == THREAD_INDEX_CRASHED && thread.stop_reason)
		        || ((uint32_t)selected_thread == thread_index);

		if (!do_thread) continue;

		if (printed_thread_already) {
			printf("\n");
		} else {
			printed_thread_already = true;
		}

		print_thread_summary(thread_index, &thread);
		print_backtrace_for_thread(core, address_space, &thread, show_locals, show_registers);
	}

	vc_address_space_free(address_space);

	return 0;

error:
	vc_address_space_free(address_space);

	return -1;
}

static int handle_command_memory(VcCore *core, int argc, const char **argv) {
	static struct option long_options[] = {
		{ "length",         required_argument, 0,  0 },
		{ 0,                0,                 0,  0 }
	};

	int length = 256;

	optind = 3; // Two arguments were already consumed

	while (1) {
		int long_option_index;
		int opt = getopt_long(argc, (char *const *)argv, "", long_options, &long_option_index);
		if (opt == -1) {
			break; // done parsing
		} else if (opt == '?') {
			goto error; // error
		} else if (opt == 0) {
			// long option
			switch (long_option_index) {
			case 0: { // --length
				char *end;
				length = strtol(optarg, &end, 10);
				if (*optarg == '\0' || *end != '\0' || length < 0) {
					fprintf(stderr, "Invalid --length argument '%s'\n", optarg);
					goto error;
				}
				break;
			}
			}
		}
	}

	if (length > 1024 * 1024) {
		fprintf(stderr, "The memory area to display can't be larger than 1 MiB.\n");
		goto error;
	}

	if (optind >= argc) {
		fprintf(stderr, "The memory command requires an address.\nSee vita-core-dump help memory.\n");
		goto error;
	}

	const char *address_as_string = argv[optind];

	char *end;
	uint32_t address = strtoul(address_as_string, &end, 16);
	if (*address_as_string == '\0' || *end != '\0') {
		fprintf(stderr, "Invalid address '%s'\n", address_as_string);
		goto error;
	}

	uint8_t *buffer;
	uint32_t bytes_read;
	if (vc_core_memory_read(core, address, length, &buffer, &bytes_read) < 0) {
		fprintf(stderr, "Data not available in core dump: %s\n", vc_core_get_error_message(core));
		goto error;
	}

	print_hex_dump(buffer, bytes_read, 32, address, 0);

	return 0;

error:
	return -1;
}

static int handle_command_modules(VcCore *core, int argc, const char **argv) {
	(void) argc;
	(void) argv;

	uint32_t module_count;
	if (vc_core_get_module_count(core, &module_count) < 0) {
		fprintf(stderr, "Failed to get module count: %s\n", vc_core_get_error_message(core));
		return -1;
	}

	for (uint32_t module_index = 0; module_index < module_count; module_index++) {
		VcModule module;
		if (vc_core_get_module(core, module_index, &module) < 0) {
			fprintf(stderr, "Failed to module %d: %s\n", module_index, vc_core_get_error_message(core));
			return -1;
		}

		printf("Module %d: %s\n", module_index, module.name);
		printf("  Start address: 0x%08x\n", module.load_address);
		printf("  Size:          %d\n", module.size);

		if (module_index != (module_count - 1)) {
			printf("\n");
		}
	}

	return 0;
}

static int handle_command_stack(VcCore *core, int argc, const char **argv) {
	static struct option long_options[] = {
		{ "add-elf",        required_argument, 0,  0 },
		{ "length",         required_argument, 0,  0 },
		{ "thread",         required_argument, 0,  0 },
		{ 0,                0,                 0,  0 }
	};

	VcAddressSpace *address_space = vc_address_space_new();
	if (vc_address_space_add_modules_from_core(address_space, core) < 0) {
		fprintf(stderr, "%s\n", vc_address_space_get_error_message(address_space));
		goto error;
	}

	int selected_thread = THREAD_INDEX_CRASHED;
	int stack_length = 20;

	optind = 3; // Two arguments were already consumed

	while (1) {
		int long_option_index;
		int opt = getopt_long(argc, (char *const *)argv, "", long_options, &long_option_index);
		if (opt == -1) {
			break; // done parsing
		} else if (opt == '?') {
			goto error; // error
		} else if (opt == 0) {
			// long option
			switch (long_option_index) {
			case 0: // --add-elf
				if (handle_argument_add_elf(optarg, address_space) < 0) {
					goto error;
				}
				break;
			case 1: {// --length
				char *end;
				stack_length = strtol(optarg, &end, 10);
				if (*optarg == '\0' || *end != '\0' || stack_length < 0) {
					fprintf(stderr, "Invalid --length argument '%s'\n", optarg);
					goto error;
				}
				break;
			}
			case 2: // --thread
				if (handle_argument_thread(optarg, &selected_thread) < 0) {
					goto error;
				}
				break;
			}
		}
	}

	uint32_t thread_count;
	if (vc_core_get_thread_count(core, &thread_count) < 0) {
		fprintf(stderr, "Failed to get thread count: %s\n", vc_core_get_error_message(core));
		goto error;
	}

	if (selected_thread >= (int)thread_count) {
		fprintf(stderr, "Invalid --thread argument '%d': there are %d threads\n", selected_thread, thread_count);
		goto error;
	}

	bool printed_thread_already = false;
	for (uint32_t thread_index = 0; thread_index < thread_count; thread_index++) {
		VcThread thread;
		if (vc_core_get_thread(core, thread_index, &thread) < 0) {
			fprintf(stderr, "Failed to get thread %d: %s\n", thread_index, vc_core_get_error_message(core));
			goto error;
		}

		bool do_thread = (selected_thread == THREAD_INDEX_ALL)
		        || (selected_thread == THREAD_INDEX_CRASHED && thread.stop_reason)
		        || ((uint32_t)selected_thread == thread_index);

		if (!do_thread) continue;

		if (printed_thread_already) {
			printf("\n");
		} else {
			printed_thread_already = true;
		}

		print_thread_summary(thread_index, &thread);
		print_stack_for_thread(core, address_space, &thread, stack_length);
	}

	vc_address_space_free(address_space);

	return 0;

error:
	vc_address_space_free(address_space);

	return -1;
}

static int handle_command_threads(VcCore *core, int argc, const char **argv) {
	static struct option long_options[] = {
		{ "show-registers", no_argument,       0,  0 },
		{ 0,                0,                 0,  0 }
	};

	bool show_registers = false;

	optind = 3; // Two arguments were already consumed

	while (1) {
		int long_option_index;
		int opt = getopt_long(argc, (char *const *)argv, "", long_options, &long_option_index);
		if (opt == -1) {
			break; // done parsing
		} else if (opt == '?') {
			return -1; // error
		} else if (opt == 0) {
			// long option
			switch (long_option_index) {
			case 0: // --show-registers
				show_registers = true;
				break;
			}
		}
	}

	uint32_t thread_count;
	if (vc_core_get_thread_count(core, &thread_count) < 0) {
		fprintf(stderr, "Failed to get thread count: %s\n", vc_core_get_error_message(core));
		return -1;
	}

	for (uint32_t thread_index = 0; thread_index < thread_count; thread_index++) {
		VcThread thread;
		if (vc_core_get_thread(core, thread_index, &thread) < 0) {
			fprintf(stderr, "Failed to get thread %d: %s\n", thread_index, vc_core_get_error_message(core));
			return -1;
		}

		print_thread_summary(thread_index, &thread);

		if (show_registers) {
			print_registers(thread.registers, 0);

			if (thread_index != (thread_count - 1)) {
				printf("\n");
			}
		}
	}

	return 0;
}

static int handle_command_help(int argc, const char **argv) {
	if (argc < 2) {
		print_usage();
		return -1;
	}

	int command = parse_command(argv[1]);
	switch (command) {
	case COMMAND_BACKTRACE:
		printf("usage: vita-core-dump <core-dump-path> backtrace [--add-elf=<elf-path>[:<hex-load-address>]]\n");
		printf("         [--thread=(<thread-index>|all|crashed)] [--show-locals] [--show-registers]\n");
		printf("\n");
		printf("Displays a backtrace for one or all of the threads of the process that generated\n");
		printf("the core dump. The default is to display only the thread that caused the crash.\n");
		printf("\n");
		printf("This command requires reading data from the process's executable.\n");
		printf("Use the --add-elf argument to set the path of the executable. The file name\n");
		printf("of the executable must match the name of the corresponding module in the\n");
		printf("core dump. See the command 'modules' for the list of modules.\n");
		printf("The executable must be the exact build that generated the core dump.\n");
		printf("\n");
		printf("It is possible to add executables that are not described in the core dump's\n");
		printf("module list. In that case, the virtual memory load address must be specified.\n");
		printf("This is useful for situations where a main program dynamically loads a library\n");
		printf("such as a plugin for example.\n");
		break;
	case COMMAND_HELP:
		print_usage();
		break;
	case COMMAND_MEMORY:
		printf("usage: vita-core-dump <core-dump-path> memory <hex-address> [--length=<bytes-to-print>]\n");
		printf("\n");
		printf("Displays a hex dump of the crashed process's memory at the specified address.\n");
		break;
	case COMMAND_MODULES:
		printf("usage: vita-core-dump <core-dump-path> modules\n");
		printf("\n");
		printf("Displays a list of all of the crashed process's loaded modules.\n");
		break;
	case COMMAND_STACK:
		printf("usage: vita-core-dump <core-dump-path> stack [--add-elf=<elf-path>[:<hex-load-address>]]\n");
		printf("         [--thread=(<thread-index>|all|crashed)] [--length=<addresses-to-print>]\n");
		printf("\n");
		printf("Displays the values on the stack of one or more thread near the stack pointer.\n");
		printf("\n");
		printf("See vita-core-dump help backtrace for more information about the --thread and --add-elf\n");
		printf("parameters.\n");
		break;
	case COMMAND_THREADS:
		printf("usage: vita-core-dump <core-dump-path> threads [--show-registers]\n");
		printf("\n");
		printf("Displays a list of all of the crashed process's threads.\n");
		break;
	default:
		fprintf(stderr, "Unknown command %s\n", argv[1]);
		print_usage();
		return -1;
	}

	return 0;
}

int main(int argc, const char **argv) {
	if (argc < 3) {
		print_usage();
		return 1;
	}

	if (strcasecmp(argv[1], "help") == 0 || strcasecmp(argv[1], "--help") == 0) {
		handle_command_help(argc - 1, argv + 1);
		return 0;
	}

	const char *core_path = argv[1];
	VcCore *core = vc_core_new();

	if (vc_core_load(core, core_path) < 0) {
		fprintf(stderr, "Failed to load core dump %s: %s\n", core_path, vc_core_get_error_message(core));
		goto error;
	}

	int command = parse_command(argv[2]);
	switch (command) {
	case COMMAND_BACKTRACE:
		if (handle_command_backtrace(core, argc, argv) < 0) {
			goto error;
		}
		break;
	case COMMAND_HELP:
		if (handle_command_help(argc - 2, argv + 2) < 0) {
			goto error;
		}
		break;
	case COMMAND_MEMORY:
		if (handle_command_memory(core, argc, argv) < 0) {
			goto error;
		}
		break;
	case COMMAND_MODULES:
		if (handle_command_modules(core, argc, argv) < 0) {
			goto error;
		}
		break;
	case COMMAND_STACK:
		if (handle_command_stack(core, argc, argv) < 0) {
			goto error;
		}
		break;
	case COMMAND_THREADS:
		if (handle_command_threads(core, argc, argv) < 0) {
			goto error;
		}
		break;
	default:
		fprintf(stderr, "Unknown command %s\n", argv[2]);
		print_usage();
		goto error;
	}

	vc_core_free(core);

	return 0;

error:
	vc_core_free(core);

	return 1;
}
