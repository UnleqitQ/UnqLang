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
	 * @param statement_index The index of the statement being compiled
	 */
	void compile_assignment(
		const assembly::assembly_memory& dest,
		const analysis::types::type_node& dest_type,
		const analysis::expressions::expression_node& src,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		uint32_t statement_index
	);

	/**
	 * This is used for the left-hand side of an assignment or accessing a variable's address.
	 * @param expr The expression to compile as a reference.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to (if needed, may not be the case).
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param statement_index The index of the statement being compiled
	 * @return The memory location of the reference.
	 */
	assembly::assembly_memory
	compile_reference(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		uint32_t statement_index
	);

	void compile_boolean_binary_expression(
		const analysis::expressions::binary_expression& binary,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		analysis::types::type_node left_type,
		analysis::types::type_node right_type,
		uint32_t statement_index
	);

	/**
	 * Compiles an expression that results in a primitive type (int, bool, char ...) or a pointer type.
	 * @param expr The expression to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param target_reg The register to store the result in.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param statement_index The index of the statement being compiled
	 * @param store_value Whether to store the computed value in the target register. If false, the expression is evaluated but the result may not be stored.
	 */
	void compile_primitive_expression(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		uint32_t statement_index,
		bool store_value = true
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
	 * @param statement_index The index of the statement being compiled
	 */
	void compile_pointer_expression(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		const analysis::types::type_node& dest_type,
		uint32_t statement_index
	);

	/**
	 * Compiles a block statement, which may contain multiple statements including variable declarations,
	 * assignments, control flow statements, and nested blocks.
	 * @param block The block statement to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param label_prefix A prefix to use for generating unique labels within this block.
	 */
	void compile_block_statement(
		const analysis::statements::block_statement& block,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		std::string label_prefix
	);

	/**
	 * Compiles a declaration statement (variable, function, struct, union, typedef).
	 * @param decl The declaration statement to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this declaration.
	 */
	void compile_declaration_statement(
		const analysis::statements::declaration_statement& decl,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		uint32_t statement_index,
		std::string label_prefix
	);

	/**
	 * Compiles an if statement, including all its branches (if, else if, else).
	 * @param if_stmt The if statement to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param statement_index The index of the statement being compiled,
	 * @param label_prefix A prefix to use for generating unique labels within this if statement.
	 */
	void compile_if_statement(
		const analysis::statements::if_statement& if_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		uint32_t statement_index,
		std::string label_prefix
	);

	/**
	 * Compiles a while or do-while statement.
	 * @param while_stmt The while statement to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this while statement.
	 */
	void compile_while_statement(
		const analysis::statements::while_statement& while_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		uint32_t statement_index,
		std::string label_prefix
	);

	/**
	 * Compiles a return statement.
	 * @param return_stmt The return statement to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this return statement.
	 */
	void compile_return_statement(
		const analysis::statements::return_statement& return_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		uint32_t statement_index,
		std::string label_prefix
	);

	/**
	 * Compiles an expression statement.
	 * @param expr_stmt The expression statement to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this expression statement.
	 */
	void compile_expression_statement(
		const analysis::expressions::expression_node& expr_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		uint32_t statement_index,
		std::string label_prefix
	);

	/**
	 * Compiles a statement (declaration, assignment, if, while, return, expression, etc.).
	 * @param statement The statement to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this statement.
	 */
	void compile_statement(
		const analysis::statements::statement_node& statement,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		uint32_t statement_index,
		std::string label_prefix
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
