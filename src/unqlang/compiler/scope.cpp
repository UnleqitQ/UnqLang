#include "scope.hpp"

#include <algorithm>
#include <ranges>

namespace unqlang::compiler {
	uint32_t scope::get_stack_size(const compilation_context& context) const {
		if (cache.calculated_stack_size)
			return cache.stack_size;
		calculate_stack_size(context);
		return cache.stack_size;
	}
	uint32_t scope::get_cumulative_stack_size(const compilation_context& context) const {
		if (cache.calculated_stack_size)
			return cache.cumulative_stack_size;
		calculate_stack_size(context);
		return cache.cumulative_stack_size;
	}
	void scope::calculate_stack_size(const compilation_context& context) const {
		if (cache.calculated_stack_size)
			return;
		uint32_t base_stack_size = 0;
		uint32_t max_stack_size = 0;
		uint32_t current_statement_index = 0;
		while (true) {
			// get next variables declared at or after current_statement_index
			auto sym_it = symbols_by_statement.lower_bound(current_statement_index);
			// get next child scope at or after current_statement_index
			auto child_it = children.lower_bound(current_statement_index);
			// if both are at the end, we're done
			if (sym_it == symbols_by_statement.end() && child_it == children.end())
				break;
			// determine which comes first (if equal, variables come first)
			if (sym_it != symbols_by_statement.end() &&
				(child_it == children.end() || sym_it->first <= child_it->first)) {
				current_statement_index = sym_it->first;
				// process variables
				for (const auto& var_name : sym_it->second) {
					const auto& var_info = symbol_table.at(var_name);
					uint32_t var_size = var_info.var_info.get_size(context);
					// as the stack grows downwards, we need to also take into account the size of the variable
					// when calculating the offset, so we first add the size, then assign the offset
					// this way, the first variable will be at -var_size, the second at -(var_size1 + var_size2), etc.

					// increase base stack size
					base_stack_size += var_size;
					// store variable offset (positive value because it's always negative relative to base pointer)
					var_info.var_info.cache.offset = base_stack_size;
				}
				if (base_stack_size > max_stack_size)
					max_stack_size = base_stack_size;
			}
			// if child scope comes first, or they are equal (variables already processed)
			if (child_it != children.end() &&
				(sym_it == symbols_by_statement.end() || child_it->first <= sym_it->first)) {
				current_statement_index = child_it->first;
				// process child scopes
				for (const auto& child_info : child_it->second) {
					uint32_t child_cumulative_size = child_info.child->get_cumulative_stack_size(context);
					uint32_t combined_size = base_stack_size + child_cumulative_size;
					if (combined_size > max_stack_size)
						max_stack_size = combined_size;
					// assign base offset for child scope
					child_info.base_offset = base_stack_size;
				}
			}
			// move to next statement index
			current_statement_index++;
		}
		cache.stack_size = base_stack_size;
		cache.cumulative_stack_size = max_stack_size;
		cache.calculated_stack_size = true;
	}
	std::shared_ptr<assembly_scope> scope::build_assembly_scope(
		const compilation_context& context,
		const std::shared_ptr<assembly_scope>& parent_scope,
		uint32_t base_offset
	) const {
		auto asm_scope = std::make_shared<assembly_scope>();
		asm_scope->parent = parent_scope;
		asm_scope->all_paths_return = all_paths_return;
		calculate_stack_size(context);
		asm_scope->stack_size = cache.stack_size;
		asm_scope->cumulative_stack_size = cache.cumulative_stack_size;
		asm_scope->base_offset = base_offset;
		// reserve space
		asm_scope->symbol_table.reserve(symbol_table.size());

		// add variables
		for (const auto& [name, var_info] : symbol_table) {
			assembly_variable_info asm_var_info;
			asm_var_info.name = name;
			asm_var_info.type = var_info.var_info.type;
			asm_var_info.size = var_info.var_info.get_size(context);
			asm_var_info.offset = base_offset + var_info.var_info.cache.offset;
			// asm_var_info.alignment = var_info.var_info.get_alignment(context); // not currently used
			asm_scope->symbol_table[name] = asm_var_info;
			uint32_t stmt_idx = var_info.statement_index;
			asm_scope->symbols_by_statement[stmt_idx].push_back(name);
		}

		// add child scopes
		for (const auto& child_list : children | std::views::values) {
			for (const auto& child_info : child_list) {
				auto child_asm_scope = child_info.child->build_assembly_scope(
					context,
					asm_scope,
					base_offset + child_info.base_offset
				);
				asm_scope->children[child_info.key] = assembly_scope::child_scope_info(child_asm_scope, child_info.key);
			}
		}
		return asm_scope;
	}

	assembly_variable_info assembly_scope::get_variable(const std::string& name, bool search_parent) const {
		if (symbol_table.contains(name)) {
			return symbol_table.at(name);
		}
		if (search_parent && parent != nullptr) {
			return parent->get_variable(name, true);
		}
		throw std::runtime_error("Variable not found in scope: " + name);
	}
	bool build_scope(
		const ast_statement_block& block,
		std::shared_ptr<scope>& out_scope,
		const std::shared_ptr<scope>& parent_scope
	) {
		out_scope = std::make_shared<scope>();
		out_scope->parent = parent_scope;
		uint32_t statement_index = 0;
		for (const auto& stmt : block.statements) {
			switch (stmt->type) {
				case ast_statement_node::type_t::ExpressionStatement:
					statement_index++;
					break;
				case ast_statement_node::type_t::FunctionDeclaration:
					throw std::runtime_error("Function declarations are not allowed inside blocks (currently)");
				case ast_statement_node::type_t::StructDeclaration:
					throw std::runtime_error("Struct declarations are not allowed inside blocks (currently)");
				case ast_statement_node::type_t::UnionDeclaration:
					throw std::runtime_error("Union declarations are not allowed inside blocks (currently)");
				case ast_statement_node::type_t::TypeDeclaration:
					throw std::runtime_error("Type declarations are not allowed inside blocks (currently)");
				case ast_statement_node::type_t::Unknown:
					throw std::runtime_error("Unknown statement type in block encountered");
				case ast_statement_node::type_t::ReturnStatement:
					// return statements always end the current block, that also means every path returns
					out_scope->all_paths_return = true;
					return true;
				case ast_statement_node::type_t::BlockStatement: {
					const auto& block_stmt = std::get<ast_statement_block>(stmt->value);
					std::shared_ptr<scope> child_scope;
					bool all_paths_return = build_scope(block_stmt, child_scope, out_scope);
					// add child scope
					child_scope_key key(statement_index, 0);
					// no other scopes at this statement index
					out_scope->children[statement_index] = {scope::child_scope_info(child_scope, key)};
					statement_index++;
					if (all_paths_return) {
						out_scope->all_paths_return = true;
						return true;
					}
					break;
				}
				case ast_statement_node::type_t::IfStatement: {
					const auto& if_stmt = std::get<ast_statement_if>(stmt->value);
					const auto mif = multi_if_statement::build_from_ast(if_stmt);
					bool all_paths_return = true;
					for (size_t i = 0; i < mif.branches.size(); i++) {
						const auto& branch = mif.branches[i];
						std::shared_ptr<scope> child_scope;
						bool branch_returns = build_scope(branch.block, child_scope, out_scope);
						// add child scope
						child_scope_key key(statement_index, static_cast<uint32_t>(i));
						out_scope->children[statement_index].emplace_back(child_scope, key);
						if (!branch_returns)
							all_paths_return = false;
					}
					statement_index++;
					if (all_paths_return) {
						out_scope->all_paths_return = true;
						return true;
					}
					break;
				}
				case ast_statement_node::type_t::WhileStatement: {
					const auto& while_stmt = std::get<ast_statement_while>(stmt->value);
					std::shared_ptr<scope> child_scope;
					const auto& body_node = while_stmt.body;
					if (body_node->type != ast_statement_node::type_t::BlockStatement) {
						throw std::runtime_error("While statement body is not a block");
					}
					const auto& body_block = std::get<ast_statement_block>(body_node->value);
					// we cannot assume that while loops always return, even if they have a return statement
					// because the loop may not execute at all
					(void) build_scope(body_block, child_scope, out_scope);
					// add child scope
					child_scope_key key(statement_index, 0);
					out_scope->children[statement_index] = {scope::child_scope_info(child_scope, key)};
					statement_index++;
					break;
				}
				case ast_statement_node::type_t::VariableDeclaration: {
					const auto& var_decl = std::get<ast_statement_variable_declaration>(stmt->value);
					if (out_scope->symbol_table.contains(var_decl.name)) {
						throw std::runtime_error("Variable '" + var_decl.name + "' already declared in this scope");
					}
					const auto& name = var_decl.name;
					const auto& type = var_decl.var_type;
					variable_info var_info(name, analysis::types::type_system::from_ast(*type));
					out_scope->symbol_table.emplace(name, scope::variable_scope_info(var_info, statement_index));
					out_scope->symbols_by_statement[statement_index].push_back(name);
					statement_index++;
					break;
				}
			}
		}
		// if we reach here, we cannot guarantee that all paths return
		out_scope->all_paths_return = false;
		return false;
	}
} // unqlang::compiler
