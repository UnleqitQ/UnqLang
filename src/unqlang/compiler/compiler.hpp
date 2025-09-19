#pragma once

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
	 * Compiles the arguments for a function call, preparing them according to the calling convention.
	 * This includes evaluating each argument expression, handling type conversions, and placing
	 * the arguments in the appropriate registers or stack locations as required by the calling convention.
	 *
	 * @param call_expr The call expression containing the function being called and its arguments.
	 * @param func_type The type of the function being called, which includes information about its parameters and return type.
	 * @param context The current compilation context, which may include information about the current scope and type system.
	 * @param program The assembly program to which the compiled instructions will be appended.
	 * @param current_scope The current assembly scope, which may be needed for variable lookups and other context-specific information.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled, useful for error reporting and debugging.
	 */
	void compile_call_arguments(
		const analysis::expressions::call_expression& call_expr,
		const analysis::types::function_type& func_type,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index
	);

	/**
	 * Compiles an inline assembly function call expression, generating the necessary assembly instructions to
	 * evaluate the function call and store the result in the specified target register.
	 * @param call The call expression to compile, which includes the function being called and its arguments.
	 * @param context The current compilation context, which may include information about the current scope and type system.
	 * @param program The assembly program to which the compiled instructions will be appended.
	 * @param current_scope The current assembly scope, which may be needed for variable lookups and other context-specific information.
	 * @param target_reg The register in which to store the result of the function call.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled, useful for error reporting and debugging.
	 * @param store_value Whether to store the return value in the target register. If false, the call will be executed but the return value may be ignored.
	 */
	void compile_inline_call_expression(
		const analysis::expressions::call_expression& call,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		bool store_value
	);

	/**
	 * Compiles a function call expression, generating the necessary assembly instructions to
	 * evaluate the function call and store the result in the specified target register.
	 *
	 * @param call The call expression to compile, which includes the function being called and its arguments.
	 * @param context The current compilation context, which may include information about the current scope and type system.
	 * @param program The assembly program to which the compiled instructions will be appended.
	 * @param current_scope The current assembly scope, which may be needed for variable lookups and other context-specific information.
	 * @param target_reg The register in which to store the result of the function call.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled, useful for error reporting and debugging.
	 * @param store_value Whether to store the return value in the target register. If false, the call will be executed but the return value may be ignored.
	 */
	void compile_call_expression(
		const analysis::expressions::call_expression& call,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		bool store_value
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
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
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
		regmask& modified_regs,
		uint32_t statement_index
	);

	/**
	 * This is used for the left-hand side of an assignment or accessing a variable's address.
	 * @param expr The expression to compile as a reference.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to (if needed, may not be the case).
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
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
		regmask& modified_regs,
		uint32_t statement_index
	);

	void compile_boolean_binary_expression(
		const analysis::expressions::binary_expression& binary,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		regmask& modified_regs,
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
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
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
		regmask& modified_regs,
		uint32_t statement_index,
		bool store_value = true
	);

	/**
	 * Compiles a memory-to-memory move operation, without doing any checks for overlapping regions.
	 *
	 * @param dest The destination memory operand where data will be moved to.
	 * @param src The source memory operand from which data will be moved.
	 * @param size The size of the data to move, in bytes.
	 * @param program The assembly program to which the compiled instructions will be appended.
	 * @param reverse If true, the move is performed in reverse order (from higher to lower addresses), useful for overlapping regions.
	 * Set this to true if destination is higher than source and regions overlap.
	 */
	void compile_move_memory(
		const assembly::assembly_memory& dest,
		const assembly::assembly_memory& src,
		uint32_t size,
		assembly::assembly_program_t& program,
		bool reverse = false
	);

	/**
	 * Compiles an expression that results in a struct type.
	 * @param expr The expression to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param target_mem The memory location to store the struct in.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param struct_type The type of the struct being compiled.
	 * @param statement_index The index of the statement being compiled
	 */
	void compile_struct_expression(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		const assembly::assembly_memory& target_mem,
		regmask used_regs,
		regmask& modified_regs,
		const analysis::types::struct_type& struct_type,
		uint32_t statement_index
	);

	/**
	 * Compiles an expression that results in a pointer type.
	 * @param expr The expression to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param target_reg The register to store the result in.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param dest_type The expected type of the pointer's pointee.
	 * @param statement_index The index of the statement being compiled
	 * @param store_value Whether to store the computed value in the target register. If false, the expression is evaluated but the result may not be stored.
	 */
	void compile_pointer_expression(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		regmask& modified_regs,
		const analysis::types::type_node& dest_type,
		uint32_t statement_index,
		bool store_value = true
	);

	struct conditional_jump_info {
		// True if the condition is a constant expression
		bool constant_condition;
		// If constant_condition is true, this is true if a jump will always be taken
		// If constant_condition is true and this is false, the jump will never be taken
		bool jump_always;
		// True if the label for no jump is used
		// That means, that a jump is done, but only to the end of the condition but not to the target label
		bool skip_jump;
		// True if the compile output needs to be inserted even if the condition is constant (side effects)
		bool side_effects;

		conditional_jump_info()
			: constant_condition(false), jump_always(false), skip_jump(false), side_effects(false) {
		}

		conditional_jump_info& as_constant(bool always) {
			constant_condition = true;
			jump_always = always;
			return *this;
		}
		conditional_jump_info& as_dynamic() {
			constant_condition = false;
			return *this;
		}
		conditional_jump_info& with_skip(bool skip) {
			skip_jump = skip;
			return *this;
		}
		conditional_jump_info& with_side_effects(bool side_eff) {
			side_effects = side_eff;
			return *this;
		}
	};

	bool contains_side_effects(
		const analysis::expressions::expression_node& expr
	);

	/**
	 * Compiles a conditional jump based on the evaluation of a condition expression.
	 * @param condition The condition expression to evaluate.
	 * @param invert If true, the jump occurs when the condition is false; if false, the jump occurs when the condition is true.
	 * @param target_label The label to jump to if the condition is met (or not met if invert is true).
	 * @param no_jump_label A label to jump to if the condition is not met (or met if invert is true).
	 * This can be used for example for short-circuit evaluation of logical AND/OR.
	 * @param needs_skip If true, a jump to no_jump_label needs to be emitted if the condition is not met (or met if invert is true).
	 * This is used for short-circuit evaluation of logical AND/OR.
	 * If false, the jump to no_jump_label may be omitted depending on the condition.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this conditional jump.
	 * @return Information about the compiled conditional jump, including whether it was optimized to a constant jump.
	 */
	conditional_jump_info compile_conditional_jump(
		const analysis::expressions::expression_node& condition,
		bool invert,
		const std::string& target_label,
		const std::string& no_jump_label,
		bool needs_skip,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		const std::string& label_prefix
	);

	/**
	 * Compiles a block statement, which may contain multiple statements including variable declarations,
	 * assignments, control flow statements, and nested blocks.
	 * @param block The block statement to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param label_prefix A prefix to use for generating unique labels within this block.
	 */
	void compile_block_statement(
		const analysis::statements::block_statement& block,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		std::string label_prefix
	);

	/**
	 * Compiles a declaration statement (variable, function, struct, union, typedef).
	 * @param decl The declaration statement to compile.
	 * @param context The current compilation context.
	 * @param program The assembly program to append to.
	 * @param current_scope The current assembly scope.
	 * @param used_regs A mask of registers that are currently in use and should not be overwritten without saving/restoring.
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this declaration.
	 */
	void compile_declaration_statement(
		const analysis::statements::declaration_statement& decl,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
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
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled,
	 * @param label_prefix A prefix to use for generating unique labels within this if statement.
	 */
	void compile_if_statement(
		const analysis::statements::if_statement& if_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
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
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this while statement.
	 */
	void compile_while_statement(
		const analysis::statements::while_statement& while_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
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
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this return statement.
	 */
	void compile_return_statement(
		const analysis::statements::return_statement& return_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
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
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this expression statement.
	 */
	void compile_expression_statement(
		const analysis::expressions::expression_node& expr_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
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
	 * @param modified_regs A mask of registers that have been modified by this compilation and need to be saved/restored.
	 * @param statement_index The index of the statement being compiled
	 * @param label_prefix A prefix to use for generating unique labels within this statement.
	 */
	void compile_statement(
		const analysis::statements::statement_node& statement,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		std::string label_prefix
	);

	class Compiler {
		struct built_in_function {
			analysis::functions::function_info info;
			assembly::assembly_program_t implementation;

			built_in_function() = default;
			built_in_function(const analysis::functions::function_info& i, const assembly::assembly_program_t& impl)
				: info(i), implementation(impl) {
			}
		};

		std::shared_ptr<analysis::types::type_system> m_type_system;
		std::shared_ptr<analysis::functions::storage> m_function_storage;
		std::shared_ptr<analysis::functions::inline_storage> m_inline_storage;
		std::unordered_map<std::string, built_in_function> m_built_in_functions;
		std::shared_ptr<analysis::variables::storage> m_variable_storage;
		std::shared_ptr<analysis::complex_literals::storage> m_complex_literal_storage;
		std::unordered_map<std::string, assembly::assembly_program_t> m_compiled_functions;
		std::vector<ast_statement_function_declaration> m_function_declarations;

	public:
		Compiler()
			: m_type_system(std::make_shared<analysis::types::type_system>()),
			  m_function_storage(std::make_shared<analysis::functions::storage>()),
			  m_variable_storage(
				  std::make_shared<analysis::variables::storage>(analysis::variables::storage::storage_type_t::Global)
			  ),
			  m_inline_storage(std::make_shared<analysis::functions::inline_storage>()),
			  m_complex_literal_storage(std::make_shared<analysis::complex_literals::storage>()) {
		}

		void analyze_program(const ast_program& program);

		void precompile_functions();

		std::shared_ptr<scope> build_function_scope(const ast_statement_function_declaration& func_decl);
		std::shared_ptr<assembly_scope> build_function_assembly_scope(
			const std::shared_ptr<scope>& func_scope);
		void compile_function(
			const ast_statement_function_declaration& func_decl,
			assembly::assembly_program_t& out_program
		);
		void compile_function(
			const std::string& func_name,
			const std::shared_ptr<assembly_function_signature>& func_sig,
			const std::shared_ptr<assembly_scope>& func_scope,
			const analysis::statements::block_statement& func_body,
			assembly::assembly_program_t& out_program
		);
		void compile_literals(assembly::assembly_program_t& out_program);

		void register_built_in_function(
			const analysis::functions::function_info& func_info,
			const assembly::assembly_program_t& program
		);
		void register_built_in_function(
			const std::string& name,
			const analysis::functions::inline_function& func
		);

		analysis::types::type_system& get_type_system() {
			return *m_type_system;
		}
		const analysis::types::type_system& get_type_system() const {
			return *m_type_system;
		}
		void compile_entry(
			const std::string& entry_function,
			assembly::assembly_program_t& out_program
		);
		assembly::assembly_program_t compile(
			const std::string& entry_function
		);
	};
} // unqlang::compiler
