#pragma once

#include <cstdint>
#include <map>

#include "variable.hpp"
#include "../analysis/statements.hpp"

namespace unqlang::compiler {
	struct scope;
	struct assembly_scope;
	struct child_scope_key {
		// index of the statement where this child scope was created
		uint32_t statement_index;
		// index of the scope in the statement (for statements that create multiple scopes, e.g. if-else)
		uint32_t scope_index;
		child_scope_key(uint32_t stmt_idx, uint32_t scp_idx = 0)
			: statement_index(stmt_idx), scope_index(scp_idx) {
		}
		// for use in std::map
		bool operator<(const child_scope_key& other) const {
			if (statement_index != other.statement_index)
				return statement_index < other.statement_index;
			return scope_index < other.scope_index;
		}
	};

	struct scope {
		// information about a child scope
		struct child_scope_info {
			// child scope
			std::shared_ptr<scope> child;
			// key of the child scope
			child_scope_key key;
			// offset from this scope's offset for this child scope's variables
			mutable uint32_t base_offset = 0;

			child_scope_info() : child(nullptr), key(0, 0) {
			}
			child_scope_info(std::shared_ptr<scope> child, child_scope_key key)
				: child(child), key(key) {
			}
		};
		// information about a variable in this scope
		struct variable_scope_info {
			// variable info
			variable_info var_info;
			// index of the statement where this variable was declared
			uint32_t statement_index;
			variable_scope_info() : statement_index(0) {
			}
			variable_scope_info(variable_info var_info, uint32_t stmt_idx)
				: var_info(var_info), statement_index(stmt_idx) {
			}
		};
		// parent scope, nullptr if global
		std::shared_ptr<scope> parent;
		// symbol name to variable info
		std::unordered_map<std::string, variable_scope_info> symbol_table;
		// statement index to variable names
		std::map<uint32_t, std::vector<std::string>> symbols_by_statement;
		// child scopes (scope index is not needed here)
		std::map<uint32_t, std::vector<child_scope_info>> children;

		// whether all code paths in this scope return
		bool all_paths_return = false;

		// cache for calculations
		mutable struct {
			bool calculated_stack_size = false;
			uint32_t stack_size = 0;
			uint32_t cumulative_stack_size = 0;
		} cache;

		// total size of local variables in this scope
		uint32_t get_stack_size(const compilation_context& context) const;
		// total size of local variables in this scope and recursively in child scopes
		uint32_t get_cumulative_stack_size(const compilation_context& context) const;
		void calculate_stack_size(const compilation_context& context) const;
		// build assembly scope from this scope
		std::shared_ptr<assembly_scope> build_assembly_scope(
			const compilation_context& context,
			const std::shared_ptr<assembly_scope>& parent_scope = nullptr,
			uint32_t base_offset = 0) const;
	};
	struct assembly_scope {
		// information about a child scope
		struct child_scope_info {
			// child scope
			std::shared_ptr<assembly_scope> child;
			// key of the child scope
			child_scope_key key;

			child_scope_info() : child(nullptr), key(0, 0) {
			}
			child_scope_info(std::shared_ptr<assembly_scope> child, child_scope_key key)
				: child(child), key(key) {
			}
		};
		// information about a variable in this scope
		struct variable_scope_info {
			// variable info
			assembly_variable_info var_info;
			// index of the statement where this variable was declared
			uint32_t statement_index;
			variable_scope_info(assembly_variable_info var_info, uint32_t stmt_idx)
				: var_info(var_info), statement_index(stmt_idx) {
			}
		};
		// parent scope, nullptr if global
		std::shared_ptr<assembly_scope> parent;
		// symbol name to variable info
		std::unordered_map<std::string, assembly_variable_info> symbol_table;
		// statement index to variable names
		std::map<uint32_t, std::vector<std::string>> symbols_by_statement;
		// child scopes
		std::map<child_scope_key, child_scope_info> children;

		// size of local variables in this scope
		uint32_t stack_size;
		// size of the local variables in this scope and recursively in child scopes
		uint32_t cumulative_stack_size;
		// offset from base pointer where this scope's variables start
		uint32_t base_offset;

		// whether all code paths in this scope return
		bool all_paths_return = false;

		assembly_scope() : parent(nullptr), stack_size(0), cumulative_stack_size(0), base_offset(0), all_paths_return(false) {
		}
		assembly_scope(std::shared_ptr<assembly_scope> parent, uint32_t base_offset = 0)
			: parent(parent), stack_size(0), cumulative_stack_size(0), base_offset(base_offset), all_paths_return(false) {
		}

		// get variable info by name, search parent scopes if not found and search_parent is true
		assembly_variable_info get_variable(const std::string& name, bool search_parent = true) const;
	};

	/**
	 * Build a scope from an AST statement block
	 * @param block AST statement block
	 * @param out_scope Output scope
	 * @param parent_scope Parent scope, nullptr if global
	 * @return True if the scope has a return statement in all code paths, false otherwise
	 */
	bool build_scope(
		const ast_statement_block& block,
		std::shared_ptr<scope>& out_scope,
		const std::shared_ptr<scope>& parent_scope = nullptr
	);
	bool build_scope(
		const analysis::statements::block_statement& block,
		std::shared_ptr<scope>& out_scope,
		const std::shared_ptr<scope>& parent_scope = nullptr
	);
} // unqlang::compiler

template<>
struct std::formatter<unqlang::compiler::scope> : std::formatter<std::string> {
	auto format(const unqlang::compiler::scope& scp, std::format_context& ctx) const {
		return std::formatter<std::string>::format(
			std::format(
				"scope(stack_size={}, cumulative_stack_size={}, variables=[{}], children={})",
				scp.get_stack_size({}),
				scp.get_cumulative_stack_size({}),
				[&scp]() {
					std::string vars;
					for (const auto& [name, var_info] : scp.symbol_table) {
						if (!vars.empty())
							vars += ", ";
						vars += std::format("{}", var_info.var_info);
					}
					return vars;
				}(),
				scp.children.size()
			),
			ctx
		);
	}
};
template<>
struct std::formatter<unqlang::compiler::assembly_scope> : std::formatter<std::string> {
	auto format(const unqlang::compiler::assembly_scope& scp, std::format_context& ctx) const {
		return std::formatter<std::string>::format(
			std::format(
				"assembly_scope(stack_size={}, cumulative_stack_size={}, base_offset={}, "
				"variables=[{}], children={}, all_paths_return={})",
				scp.stack_size,
				scp.cumulative_stack_size,
				scp.base_offset,
				[&scp]() {
					std::string vars;
					for (const auto& [name, var_info] : scp.symbol_table) {
						if (!vars.empty())
							vars += ", ";
						vars += std::format("{}", var_info);
					}
					return vars;
				}(),
				scp.children.size(),
				scp.all_paths_return
			),
			ctx
		);
	}
};
