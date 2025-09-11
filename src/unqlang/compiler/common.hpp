#pragma once
#include <cstdint>

#include "../analysis/types.hpp"
#include "../analysis/functions.hpp"
#include "../analysis/expressions.hpp"
#include "../analysis/variables.hpp"

namespace unqlang::compiler {
	union regmask {
		struct {
			uint8_t eax : 1;
			uint8_t ebx : 1;
			uint8_t ecx : 1;
			uint8_t edx : 1;
			uint8_t esi : 1;
			uint8_t edi : 1;
			uint8_t ebp : 1;
			uint8_t esp : 1;
			// eip is not included as there is no way to use it directly
		};
		uint16_t raw;
	};
	struct compilation_context {
		// type system for type information
		std::shared_ptr<analysis::types::type_system> type_system;

		// function storage (for global functions)
		std::shared_ptr<analysis::functions::storage> function_storage;

		// variable storage (for global variables)
		std::shared_ptr<analysis::variables::storage> variable_storage;

		compilation_context()
			: type_system(std::make_shared<analysis::types::type_system>()),
			  function_storage(std::make_shared<analysis::functions::storage>()),
			  variable_storage(std::make_shared<analysis::variables::storage>()) {
		}

		compilation_context(const std::shared_ptr<analysis::types::type_system>& ts,
			const std::shared_ptr<analysis::functions::storage>& fs,
			const std::shared_ptr<analysis::variables::storage>& vs)
			: type_system(ts), function_storage(fs), variable_storage(vs) {
			if (!type_system) {
				throw std::runtime_error("Type system cannot be null");
			}
			if (!function_storage) {
				throw std::runtime_error("Function storage cannot be null");
			}
			if (!variable_storage) {
				throw std::runtime_error("Variable storage cannot be null");
			}
		}
	};

	struct scoped_compilation_context {
		// global context
		std::shared_ptr<compilation_context> global_context;

		// parent context
		std::shared_ptr<scoped_compilation_context> parent_context;

		// variable storage for this scope
		std::shared_ptr<analysis::variables::storage> variable_storage;

		scoped_compilation_context(
			const std::shared_ptr<compilation_context>& global_ctx,
			const std::shared_ptr<scoped_compilation_context>& parent_ctx = nullptr)
			: global_context(global_ctx),
			  parent_context(parent_ctx),
			  variable_storage(std::make_shared<analysis::variables::storage>()) {
			if (!global_context) {
				throw std::runtime_error("Global context cannot be null");
			}
		}
	};

	struct multi_if_statement {
		struct branch {
			// condition, nullptr for else branch
			std::shared_ptr<ast_expression_node> condition;
			// block to execute if condition is true (or else branch)
			ast_statement_block block;
			branch(ast_statement_block blk, std::shared_ptr<ast_expression_node> cond = nullptr)
				: condition(cond), block(blk) {
			}
		};
		std::vector<branch> branches;

		multi_if_statement() : branches() {
		}
		multi_if_statement(std::vector<branch> branches) : branches(branches) {
		}

		void add_branch(ast_statement_block block, std::shared_ptr<ast_expression_node> condition = nullptr) {
			if (condition == nullptr && (branches.empty() || branches.back().condition == nullptr)) {
				if (branches.empty())
					throw std::runtime_error("Cannot add else branch to multi_if_statement without any prior branches");
				throw std::runtime_error("Cannot add multiple else branches to multi_if_statement");
			}
			branches.emplace_back(block, condition);
		}

		static multi_if_statement build_from_ast(const ast_statement_if& if_stmt) {
			multi_if_statement mif;
			const ast_statement_if* current = &if_stmt;
			while (true) {
				const auto& if_node = current->then_branch;
				if (if_node->type != ast_statement_node::type_t::BlockStatement) {
					throw std::runtime_error("If statement then branch is not a block");
				}
				mif.add_branch(std::get<ast_statement_block>(if_node->value), current->condition);
				if (current->else_branch == nullptr) {
					break;
				}
				if (current->else_branch->type == ast_statement_node::type_t::IfStatement) {
					current = &std::get<ast_statement_if>(current->else_branch->value);
				}
				else if (current->else_branch->type == ast_statement_node::type_t::BlockStatement) {
					mif.add_branch(std::get<ast_statement_block>(current->else_branch->value), nullptr);
					break;
				}
				else {
					throw std::runtime_error("If statement else branch is not an if statement or block");
				}
			}
			return mif;
		}
	};
} // unqlang::compiler

template<>
struct std::formatter<unqlang::compiler::regmask> : std::formatter<std::string> {
	auto format(const unqlang::compiler::regmask& rm, std::format_context& ctx) const {
		std::string regs;
		if (rm.eax)
			regs += "AX ";
		else
			regs += "-- ";
		if (rm.ebx)
			regs += "BX ";
		else
			regs += "-- ";
		if (rm.ecx)
			regs += "CX ";
		else
			regs += "-- ";
		if (rm.edx)
			regs += "DX ";
		else
			regs += "-- ";
		if (rm.esi)
			regs += "SI ";
		else
			regs += "-- ";
		if (rm.edi)
			regs += "DI ";
		else
			regs += "-- ";
		if (rm.ebp)
			regs += "BP ";
		else
			regs += "-- ";
		if (rm.esp)
			regs += "SP ";
		else
			regs += "-- ";
		return std::formatter<std::string>::format(regs, ctx);
	}
};
