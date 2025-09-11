#pragma once

#include <optional>

#include "variable.hpp"
#include "function.hpp"
#include "scope.hpp"
#include "../../assembly/assembly.hpp"

namespace unqlang::compiler {
	struct compilation_function {
		function_info info;
		std::optional<assembly_function_info> assembly_info;
	};

	void compile_expression(
		const ast_expression_node& expr,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg
	);

	class Compiler {
	};
} // unqlang::compiler
