// ps2plugininjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <memory>
#include <fstream>
#include <filesystem>
#include "elfio.hpp"
#include "Patterns.h"


using namespace ELFIO;
using namespace hook::txn;

struct injector_config {
	char name[128];
	char version[8];
	int  ei_offset;
	int  base_address;
};

void makeJal(const void* addr, const unsigned int func)
{
	*(int*)addr = ((0x0C000000 | (((unsigned int)func & 0x0fffffff) >> 2)));
}


section* get_section(elfio& elf, const char* name)
{
	section* result = nullptr;
	for (int i = 0; i < elf.sections.size(); i++)
	{
		section* sec = elf.sections[i];
		if (strcmp(sec->get_name().c_str(), name) == 0)
		{
			result = sec;
			break;
		}
	}
	return result;
}

uint32_t get_symbol_addr(elfio& elf, const char* symName)
{
	uint32_t result = 0;
	for (int i = 0; i < elf.sections.size(); i++)
	{
		section* sec = elf.sections[i];
		if (sec->get_type() == SHT_SYMTAB)
		{
			const_symbol_section_accessor symbols(elf, sec);
			int num_symbols = symbols.get_symbols_num();

			for (int i = 0; i < num_symbols; i++)
			{
				std::string   name;
				Elf64_Addr    value = 0;
				Elf_Xword     size = 0;
				unsigned char bind = 0;
				unsigned char type = 0;
				Elf_Half      section = 0;
				unsigned char other = 0;
				symbols.get_symbol(i, name, value, size, bind, type,
					section, other);
				if (strcmp(symName, name.c_str()) == 0)
				{
					result = value;
					break;
				}
			}
		}

	}
	return result;
}


int main(int argc, char* argv[])
{
	if (argc == 1) {
		std::cout << "Usage: ps2plugininjector <params> <input executable>\n"
			<< "    -o <filename>   (optional) Sets output filename.\n"
			<< "    -i <plugin>     Plugin file to inject.\n"
			<< "    -p <patchfile>  Patch file to use as guidance.\n";

		return 1;
	}

	std::ifstream patchFile;

	std::string o_param;
	std::string i_param;

	// params
	for (int i = 1; i < argc - 1; i++)
	{
		if (argv[i][0] != '-' || strlen(argv[i]) != 2) {
			return 1;
		}
		switch (argv[i][1])
		{
		case 'p':
			i++;
			patchFile = std::ifstream(argv[i]);
			break;
		case 'o':
			i++;
			o_param = argv[i];
			break;
		case 'i':
			i++;
			i_param = argv[i];
			break;
		default:
			std::cout << "ERROR: Param does not exist: " << argv[i] << std::endl;
			return 0;
			break;
		}
	}


	elfio src_elf;
	elfio plugin_elf;



	std::string input = argv[argc - 1];

	if (i_param.empty())
	{
		std::cout << "ERROR: Plugin file was not specified!" << std::endl;
		return 0;
	}

	std::string plugin_input = i_param;


	std::cout << "INFO: Reading executable" << std::endl;

	if (!src_elf.load(argv[argc - 1]))
	{
		std::cout << "ERROR: Could not open or load " << argv[argc - 1] << std::endl;
		return 0;
	}

	section* src_code_data = get_section(src_elf, ".text");
	if (src_code_data == nullptr)
	{
		std::cout << "ERROR: Could not find .text section in the source file!" << std::endl;
		return 0;
	}

	{
		section* plugin_section = get_section(src_elf, ".plugin");
		if (plugin_section)
		{
			std::cout << "ERROR: This ELF has a plugin already injected! Aborting." << std::endl;
			return 0;
		}
	}


	std::cout << "INFO: Reading plugin" << std::endl;

	if (!plugin_elf.load(plugin_input))
	{
		std::cout << "ERROR: Could not open or load plugin" << plugin_input << std::endl;
		return 0;
	}



	section* plugin_code_data = get_section(plugin_elf, ".text");
	if (plugin_code_data == nullptr)
	{
		std::cout << "ERROR: Could not find .text section in the plugin file!" << std::endl;
		return 0;
	}

	std::cout << "INFO: Reading patch file and applying patches" << std::endl;

	auto buff = std::make_unique<char[]>(src_code_data->get_size());
	memcpy(buff.get(), src_code_data->get_data(), src_code_data->get_size());

	{
		std::string nextPatchLine;
		while (std::getline(patchFile, nextPatchLine))
		{
			unsigned int nextPatchAddr = std::stoul(nextPatchLine.substr(0, 8), nullptr, 16);
			std::string nextPatchSymbol = nextPatchLine.substr(8);

			if (!nextPatchSymbol._Starts_with("@"))
			{
				std::cout << "ERROR: Patch file was not formatted properly" << std::endl;
				return 0;
			}

			uint32_t nextPatchFunc = get_symbol_addr(plugin_elf, nextPatchSymbol.substr(1).c_str());
			if (nextPatchFunc == 0)
			{
				std::cout << "ERROR: Could not find \"" << nextPatchSymbol << "\" function in the plugin file!" << std::endl;
				return 0;
			}

			makeJal(buff.get() + nextPatchAddr - src_code_data->get_address(), nextPatchFunc);
		}

		src_code_data->set_data(buff.get(), src_code_data->get_size());
	}

	{
		std::cout << "INFO: Copying plugin code section & segment" << std::endl;

		section* new_plugin_section = src_elf.sections.add(".plugin");
		new_plugin_section->set_type(plugin_code_data->get_type());
		new_plugin_section->set_flags(plugin_code_data->get_flags());
		new_plugin_section->set_addr_align(plugin_code_data->get_addr_align());
		new_plugin_section->set_entry_size(plugin_code_data->get_entry_size());


		new_plugin_section->set_data(plugin_code_data->get_data(), plugin_code_data->get_size());
		segment* text_seg = src_elf.segments.add();
		text_seg->set_type(PT_LOAD);
		text_seg->set_virtual_address(plugin_code_data->get_address());
		text_seg->set_physical_address(plugin_code_data->get_address());
		text_seg->set_flags(PF_W | PF_X | PF_R);
		text_seg->set_align(plugin_code_data->get_addr_align());
		text_seg->add_section_index(new_plugin_section->get_index(),
			new_plugin_section->get_addr_align());
		text_seg->set_memory_size(plugin_code_data->get_size());

	}

	std::cout << "INFO: Adding plugin info" << std::endl;

	section* note_sec = src_elf.sections.add(".plugin_note");
	note_sec->set_type(SHT_NOTE);
	note_section_accessor note_writer(src_elf, note_sec);
	note_writer.add_note(0x01, "PS2PLUGININJECTOR", "patched", 8);

	std::cout << "INFO: Saving result" << std::endl;

	std::string output;
	if (o_param.empty())
	{
		output = input;
		output += "_patched";
		std::cout << "INFO: Output was not specified, the file will be saved as " << output << std::endl;
	}
	else
		output = o_param;

	src_elf.save(output);

	std::cout << "INFO: Finished!" << std::endl;
	return 1;

}
