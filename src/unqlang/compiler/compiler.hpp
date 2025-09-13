#pragma once

#include <optional>

#include "variable.hpp"
#include "function.hpp"
#include "scope.hpp"
#include "../../assembly/assembly.hpp"
#include "../analysis/expressions.hpp"

namespace unqlang::compiler {
	/**
	 * Generates a unique label for a function based on its name.
	 *
	 * Important: The generated label should be unique and consistent for the same function signature.
	 *
	 * @warning Currently this does ignore parameters and therefore does not support overloading. This will be changed in the future.
	 * @param name The name of the function.
	 * @return A unique label string for the function.
	 */
	std::string generate_function_label(
		const std::string& name
	);

	/**
	 * Compiles an assignment operation from a source expression to a destination memory location.
	 * @param dest The destination memory location where the result will be stored.
	 * @param dest_type The type of the destination.
	 * @param src The source expression to compile and assign.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 */
	void compile_assignment(
		const assembly::assembly_memory& dest,
		const analysis::types::type_node& dest_type,
		const analysis::expressions::expression_node& src,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs
	);

	/**
	 * This is used for the left-hand side of an assignment or accessing a variable's address.
	 * @param expr The expression to compile as a reference.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to (if needed, may not be the case).
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @return The memory location of the reference.
	 */
	assembly::assembly_memory
	compile_reference(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs
	);

	void compile_boolean_binary_expression(
		const analysis::expressions::binary_expression& binary,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		analysis::types::type_node left_type,
		analysis::types::type_node right_type
	);

	/**
	 * Compiles an expression that results in a primitive type (int, bool, char ...) or a pointer type.
	 * @param expr The expression to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param target_reg The register to store the result in.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 */
	void compile_primitive_expression(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs
	);

	/**
	 * Compiles an expression that results in a pointer type.
	 * @param expr The expression to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param target_reg The register to store the result in.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param dest_type The expected type of the pointer's pointee.
	 */
	void compile_pointer_expression(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		const analysis::types::type_node& dest_type
	);

	class Compiler {
		std::shared_ptr<analysis::types::type_system> m_type_system;
		std::shared_ptr<analysis::functions::storage> m_function_storage;
		std::shared_ptr<analysis::variables::storage> m_variable_storage;

	public:
		Compiler()
			: m_type_system(std::make_shared<analysis::types::type_system>()),
			  m_function_storage(std::make_shared<analysis::functions::storage>()),
			  m_variable_storage(std::make_shared<analysis::variables::storage>()) {
		}

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
