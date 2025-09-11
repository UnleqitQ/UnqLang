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
		std::shared_ptr<analysis::types::type_system> m_type_system;

	public:
		void analyze_program(const ast_program& program);

		std::shared_ptr<scope> build_function_scope(const ast_statement_function_declaration& func_decl);
		std::shared_ptr<assembly_scope> build_function_assembly_scope(
			const std::shared_ptr<scope>& func_scope);

		analysis::types::type_system& get_type_system() {
			return *m_type_system;
		}
		const analysis::types::type_system& get_type_system() const {
			return *m_type_system;
		}
	};
} // unqlang::compiler
