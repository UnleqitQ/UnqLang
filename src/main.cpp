#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ranges>
#include <typeinfo>
#include <format>
#include <random>

#include <cmrc/cmrc.hpp>

#include "assembly/assembly_parser.hpp"
#include "machine/computer.hpp"
#include "unqlang/lexer.hpp"
#include "unqlang/ast.hpp"
#include "unqlang/compiler/compiler.hpp"

CMRC_DECLARE(builtin);

void build_ast(const std::string& source_code, unqlang::ast_program& out_program) {
	auto tokens = unqlang::run_lexer(source_code);
	std::vector<unqlang::lexer_token> filtered_tokens;
	filtered_tokens.reserve(tokens.size());
	for (const auto& token : tokens) {
		if (token.type != unqlang::lexer_token::type_t::Comment) {
			filtered_tokens.push_back(token);
		}
	}
	try {
		out_program = unqlang::parse_ast_program(filtered_tokens);
	}
	catch (const std::exception& e) {
		std::cerr << "Error parsing AST: " << e.what() << std::endl;
		throw;
	}
}

void print_scope(const unqlang::compiler::scope& scp, int indent = 0) {
	std::string indent_str(indent * 2, ' ');
	std::cout << indent_str << "Scope:\n";
	std::cout << indent_str << std::format(
		"all_paths_return={}\n",
		scp.all_paths_return ? "true" : "false"
	);
	if (scp.symbol_table.empty()) {
		std::cout << indent_str << "Variables: None\n";
	}
	else {
		std::cout << indent_str << "Variables:\n";
		for (const auto& [key, names] : scp.symbols_by_statement) {
			std::cout << indent_str << "  At statement index " << key << ":\n";
			for (const auto& name : names) {
				const auto& var_info = scp.symbol_table.at(name);
				std::cout << indent_str << "    " <<
					std::format("{}: type='{}'",
						var_info.var_info.name,
						var_info.var_info.type
					)
					<< "\n";
			}
		}
	}
	if (scp.children.empty()) {
		std::cout << indent_str << "Children: None\n";
	}
	else {
		std::cout << indent_str << "Children:\n";
		for (const auto& [key, child_list] : scp.children) {
			std::cout << indent_str << "  Child at statement index " << key << ":\n";
			for (const auto& child_info : child_list) {
				std::cout << indent_str << "    Child scope:\n";
				print_scope(*child_info.child, indent + 3);
			}
		}
	}
}

void print_asm_scope(const unqlang::compiler::assembly_scope& scp, int indent = 0) {
	std::string indent_str(indent * 2, ' ');
	std::cout << indent_str << "Assembly Scope: ";
	std::cout << std::format(
		"stack_size={}, "
		"cumulative_stack_size={}, "
		"base_offset={},\n",
		scp.stack_size,
		scp.cumulative_stack_size,
		scp.base_offset
	);
	std::cout << indent_str << "all_paths_return=" << (scp.all_paths_return ? "true" : "false") << "\n";
	if (scp.symbol_table.empty()) {
		std::cout << indent_str << "Variables: None\n";
	}
	else {
		std::cout << indent_str << "Variables:\n";
		for (const auto& [key, names] : scp.symbols_by_statement) {
			std::cout << indent_str << "  At statement index " << key << ":\n";
			for (const auto& name : names) {
				const auto& var_info = scp.symbol_table.at(name);
				std::cout << indent_str << "    " <<
					std::format("{}: type='{}', size={}, offset={}",
						var_info.name,
						var_info.type,
						var_info.size,
						var_info.offset)
					<< "\n";
			}
		}
	}
	if (scp.children.empty()) {
		std::cout << indent_str << "Children: None\n";
	}
	else {
		std::cout << indent_str << "Children:\n";
		for (const auto& [key, child_info] : scp.children) {
			std::cout << indent_str << "  Child at statement index " << key.statement_index
				<< ", scope index " << key.scope_index << ":\n";
			std::cout << indent_str << "    Child assembly scope:\n";
			print_asm_scope(*child_info.child, indent + 3);
		}
	}
}

assembly::assembly_program_t parse_assembly(const std::string& source_code) {
	std::vector<assembly::assembly_token> assembly_tokens = assembly::run_lexer(source_code);

	// Clean up tokens: remove comments and join newlines
	assembly::remove_comments(assembly_tokens);
	std::vector<assembly::assembly_token> cleaned_tokens;
	assembly::join_newlines(assembly_tokens, cleaned_tokens);
	assembly_tokens = cleaned_tokens;

	std::vector<assembly::assembly_parse_component> assembly_components = assembly::run_component_parser(assembly_tokens);

	assembly::assembly_program_t assembly_program = assembly::run_parser(assembly_components);
	return assembly_program;
}

void register_built_in_functions(unqlang::compiler::Compiler& compilr) {
	cmrc::embedded_filesystem cmrc_fs = cmrc::builtin::get_filesystem();

	// putc
	try {
		auto file = cmrc_fs.open("builtin/putc.usm");
		std::string putc_asm(file.begin(), file.end());
		compilr.register_built_in_function(
			"putc",
			unqlang::analysis::functions::inline_function(
				unqlang::analysis::functions::inline_function::parameter_info(
					unqlang::analysis::types::primitive_type::VOID,
					{machine::register_id::eax, machine::register_access::low_byte}
				),
				{
					unqlang::analysis::functions::inline_function::parameter_info(
						unqlang::analysis::types::primitive_type::CHAR,
						{machine::register_id::eax, machine::register_access::low_byte}
					)
				},
				parse_assembly(putc_asm)
			)
		);
	}
	catch (const std::exception& e) {
		std::cerr << "Error loading putc.usm: " << e.what() << std::endl;
		throw;
	}

	// puti
	try {
		auto file = cmrc_fs.open("builtin/puti.usm");
		std::string puti_asm(file.begin(), file.end());
		compilr.register_built_in_function(
			unqlang::analysis::functions::function_info("puti",
				unqlang::analysis::types::primitive_type::VOID,
				{unqlang::analysis::types::primitive_type::INT}
			), parse_assembly(puti_asm)
		);
	}
	catch (const std::exception& e) {
		std::cerr << "Error loading puti.usm: " << e.what() << std::endl;
		throw;
	}

	// dev_in
	try {
		auto file = cmrc_fs.open("builtin/dev_in.usm");
		std::string dev_in_asm(file.begin(), file.end());
		compilr.register_built_in_function(
			"dev_in",
			unqlang::analysis::functions::inline_function(
				unqlang::analysis::functions::inline_function::parameter_info(
					unqlang::analysis::types::primitive_type::USHORT,
					{machine::register_id::edx, machine::register_access::word}
				),
				{
					unqlang::analysis::functions::inline_function::parameter_info(
						unqlang::analysis::types::primitive_type::UINT,
						{machine::register_id::eax, machine::register_access::dword}
					)
				},
				parse_assembly(dev_in_asm)
			)
		);
	}
	catch (const std::exception& e) {
		std::cerr << "Error loading dev_in.usm: " << e.what() << std::endl;
		throw;
	}

	// dev_out
	try {
		auto file = cmrc_fs.open("builtin/dev_out.usm");
		std::string dev_out_asm(file.begin(), file.end());
		compilr.register_built_in_function(
			"dev_out",
			unqlang::analysis::functions::inline_function(
				unqlang::analysis::functions::inline_function::parameter_info(
					unqlang::analysis::types::primitive_type::VOID,
					{machine::register_id::eax, machine::register_access::dword}
				),
				{
					unqlang::analysis::functions::inline_function::parameter_info(
						unqlang::analysis::types::primitive_type::USHORT,
						{machine::register_id::edx, machine::register_access::word}
					),
					unqlang::analysis::functions::inline_function::parameter_info(
						unqlang::analysis::types::primitive_type::UINT,
						{machine::register_id::eax, machine::register_access::dword}
					)
				},
				parse_assembly(dev_out_asm)
			)
		);
	}
	catch (const std::exception& e) {
		std::cerr << "Error loading dev_out.usm: " << e.what() << std::endl;
		throw;
	}

	// rd
	try {
		auto file = cmrc_fs.open("builtin/rd.usm");
		std::string rd_asm(file.begin(), file.end());
		compilr.register_built_in_function(
			"rd",
			unqlang::analysis::functions::inline_function(
				unqlang::analysis::functions::inline_function::parameter_info(
					unqlang::analysis::types::primitive_type::UINT,
					{machine::register_id::eax, machine::register_access::dword}
				),
				{},
				parse_assembly(rd_asm)
			)
		);
	}
	catch (const std::exception& e) {
		std::cerr << "Error loading rd.usm: " << e.what() << std::endl;
		throw;
	}

	// dbg
	try {
		auto file = cmrc_fs.open("builtin/dbg.usm");
		std::string dbg_asm(file.begin(), file.end());
		compilr.register_built_in_function(
			"dbg",
			unqlang::analysis::functions::inline_function(
				unqlang::analysis::functions::inline_function::parameter_info(
					unqlang::analysis::types::primitive_type::VOID,
					{machine::register_id::eax, machine::register_access::dword}
				),
				{
					unqlang::analysis::functions::inline_function::parameter_info(
						unqlang::analysis::types::primitive_type::UINT,
						{machine::register_id::eax, machine::register_access::dword}
					)
				},
				parse_assembly(dbg_asm)
			)
		);
	}
	catch (const std::exception& e) {
		std::cerr << "Error loading dbg.usm: " << e.what() << std::endl;
		throw;
	}
}

int main() {
	std::filesystem::path source_path = "../programs/quicksort.unq";
	std::string source_code;
	try {
		if (!std::filesystem::exists(source_path)) {
			std::cerr << "Source file does not exist: " << source_path << std::endl;
			return 1;
		}
		std::ifstream source_file(source_path);
		if (!source_file.is_open()) {
			std::cerr << "Error opening source file: " << source_path << std::endl;
			return 1;
		}
		source_code = std::string((std::istreambuf_iterator<char>(source_file)),
			std::istreambuf_iterator<char>());
		source_file.close();
	}
	catch (const std::exception& e) {
		std::cerr << "Error reading source file: " << e.what() << std::endl;
		return 1;
	}

	unqlang::ast_program program;
	try {
		build_ast(source_code, program);
	}
	catch (const std::exception& e) {
		std::cerr << "Error building AST: " << e.what() << std::endl;
		return 1;
	}

	std::cout << std::endl << "AST built successfully." << std::endl << std::endl;

	unqlang::compiler::Compiler compilr;
	compilr.analyze_program(program);

	// register built-in functions
	try {
		register_built_in_functions(compilr);
	}
	catch (const std::exception& e) {
		std::cerr << "Error registering built-in functions: " << e.what() << std::endl;
		return 1;
	}

	assembly::assembly_program_t full_program;
	try {
		full_program = compilr.compile("main");
	}
	catch (const std::exception& e) {
		std::cerr << "Error compiling entry function: " << e.what() << std::endl;
		return 1;
	}
	std::cout << "Full assembly program after compiling entry function 'main':" << std::endl;
	for (const auto& instr : full_program) {
		std::cout << std::format("{:i}", instr) << std::endl;
	}
	std::cout << std::endl;
	std::cout << std::string(80, '=') << std::endl;
	std::cout << "Assembling and running program..." << std::endl;
	std::cout << std::endl;

	machine::computer computr;
	uint32_t program_start_address = machine::ram::SIZE / 3;
	machine::program_t machine_program;
	try {
		machine_program = assembly::assemble(
			full_program, true, program_start_address
		);
	}
	catch (const std::exception& e) {
		std::cerr << "Error assembling program: " << e.what() << std::endl;
		return 1;
	}
	try {
		computr.load_program(machine_program, program_start_address);
	}
	catch (const std::exception& e) {
		std::cerr << "Error loading program into computer: " << e.what() << std::endl;
		return 1;
	}

	machine::peripheral stdio_peripheral(
		0x0001,
		[]() {
			char input_char;
			std::cin.get(input_char);
			return static_cast<uint32_t>(input_char);
		},
		[](uint32_t value) {
			std::cout << static_cast<char>(value & 0xFF);
		}
	);
	computr.register_peripheral(stdio_peripheral);

	machine::peripheral time_peripheral(
		0x0002,
		[] {
			auto now = std::chrono::high_resolution_clock::now();
			auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
			auto epoch = now_ms.time_since_epoch();
			return static_cast<uint32_t>(epoch.count() & 0xFFFFFFFF);
		},
		[](uint32_t value) {
			// No-op for write
		}
	);
	computr.register_peripheral(time_peripheral);

	std::mt19937 mt(std::random_device{}());
	machine::peripheral rand_peripheral(
		0x0003,
		[&mt] {
			std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
			return dist(mt);
		},
		[](uint32_t value) {
			// No-op for write
		}
	);
	computr.register_peripheral(rand_peripheral);

	machine::peripheral keyboard_peripheral(
		0x0004,
		[] {
			if (std::cin.rdbuf()->in_avail() > 0) {
				char input_char;
				std::cin.get(input_char);
				return static_cast<uint32_t>(input_char);
			}
			else {
				return static_cast<uint32_t>(0);
			}
		},
		[](uint32_t value) {
			// No-op for write
		}
	);
	computr.register_peripheral(keyboard_peripheral);

	machine::peripheral debug_peripheral(
		0xFFFF,
		[] {
			return 0;
		},
		[](uint32_t value) {
			std::cout << std::format("[DEBUG] Peripheral write: {:#010x}\n", value);
		}
	);
	computr.register_peripheral(debug_peripheral);

	computr.set_verbose(false);
	try {
		computr.run();
	}
	catch (const std::exception& e) {
		std::cerr << "Error during execution: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}
