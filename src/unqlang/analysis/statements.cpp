#include "statements.hpp"

#include "../compiler/common.hpp"

namespace unqlang::analysis::statements {
	block_statement block_statement::from_ast(
		const ast_statement_block& ast_block
	) {
		block_statement result;
		for (const auto& ast_stmt_ptr : ast_block.statements) {
			if (ast_stmt_ptr) {
				result.statements.push_back(
					std::make_shared<statement_node>(statement_node::from_ast(*ast_stmt_ptr)));
			}
		}
		return result;
	}
	declaration_variable_statement declaration_variable_statement::from_ast(
		const ast_statement_variable_declaration& ast_var_decl
	) {
		declaration_variable_statement result;
		result.type = types::type_system::from_ast(*ast_var_decl.var_type);
		result.name = ast_var_decl.name;
		if (ast_var_decl.initializer) {
			result.initializer = expressions::expression_node::from_ast(*ast_var_decl.initializer);
		}
		else {
			result.initializer = std::nullopt;
		}
		return result;
	}
	declaration_function_statement declaration_function_statement::from_ast(
		const ast_statement_function_declaration& ast_func_decl
	) {
		declaration_function_statement result;
		result.name = ast_func_decl.name;
		result.return_type = types::type_system::from_ast(*ast_func_decl.return_type);
		for (const auto& [param_name, param_type_ast] : ast_func_decl.parameters) {
			parameter param;
			if (!param_name.empty()) {
				param.name = param_name;
			}
			param.type = types::type_system::from_ast(*param_type_ast);
			result.parameters.push_back(std::move(param));
		}
		if (ast_func_decl.body) {
			result.body = block_statement::from_ast(*ast_func_decl.body);
		}
		else {
			result.body = std::nullopt;
		}
		return result;
	}
	declaration_struct_statement declaration_struct_statement::from_ast(
		const ast_statement_struct_declaration& ast_struct_decl
	) {
		declaration_struct_statement result;
		result.name = ast_struct_decl.name;
		result.type = types::struct_type{};
		result.type->members.reserve(ast_struct_decl.body->members.size());
		for (const auto& ast_member : ast_struct_decl.body->members) {
			types::struct_type::member member;
			result.type->members.emplace_back(
				ast_member.name,
				std::make_shared<types::type_node>(types::type_system::from_ast(*ast_member.type))
			);
		}
		return result;
	}
	declaration_union_statement declaration_union_statement::from_ast(
		const ast_statement_union_declaration& ast_union_decl
	) {
		declaration_union_statement result;
		result.name = ast_union_decl.name;
		result.type = types::union_type{};
		result.type->members.reserve(ast_union_decl.body->members.size());
		for (const auto& ast_member : ast_union_decl.body->members) {
			types::union_type::member member;
			result.type->members.emplace_back(
				ast_member.name,
				std::make_shared<types::type_node>(types::type_system::from_ast(*ast_member.type))
			);
		}
		return result;
	}
	declaration_typedef_statement declaration_typedef_statement::from_ast(
		const ast_statement_type_declaration& ast_typedef_decl
	) {
		declaration_typedef_statement result;
		result.alias_name = ast_typedef_decl.name;
		result.aliased_type = types::type_system::from_ast(*ast_typedef_decl.aliased_type);
		return result;
	}
	while_statement while_statement::from_ast(
		const ast_statement_while& ast_while
	) {
		while_statement result;
		result.condition = expressions::expression_node::from_ast(*ast_while.condition);
		if (ast_while.body->type != ast_statement_node::type_t::BlockStatement) {
			throw std::runtime_error("While statement body must be a block");
		}
		result.body = block_statement::from_ast(std::get<ast_statement_block>(ast_while.body->value));
		result.is_do_while = false; // Do-while loops are not supported yet
		return result;
	}
	if_statement if_statement::from_ast(
		const ast_statement_if& ast_if
	) {
		if_statement result;
		compiler::multi_if_statement multi_if = compiler::multi_if_statement::build_from_ast(ast_if);
		result.clauses.reserve(multi_if.branches.size());
		for (const auto& branch : multi_if.branches) {
			result.clauses.emplace_back(
				block_statement::from_ast(branch.block),
				branch.condition
				? std::optional<expressions::expression_node>(
					expressions::expression_node::from_ast(*branch.condition))
				: std::nullopt
			);
		}
		return result;
	}
	return_statement return_statement::from_ast(const ast_statement_return& ast_return) {
		return_statement result;
		if (ast_return.value) {
			result.value = expressions::expression_node::from_ast(*ast_return.value);
		}
		else {
			result.value = std::nullopt;
		}
		return result;
	}
	statement_node statement_node::from_ast(const ast_statement_node& ast_stmt) {
		switch (ast_stmt.type) {
			case ast_statement_node::type_t::VariableDeclaration: {
				const auto& var_decl = std::get<ast_statement_variable_declaration>(ast_stmt.value);
				return statement_node(declaration_variable_statement::from_ast(var_decl));
			}
			case ast_statement_node::type_t::FunctionDeclaration: {
				const auto& func_decl = std::get<ast_statement_function_declaration>(ast_stmt.value);
				return statement_node(declaration_function_statement::from_ast(func_decl));
			}
			case ast_statement_node::type_t::StructDeclaration: {
				const auto& struct_decl = std::get<ast_statement_struct_declaration>(ast_stmt.value);
				return statement_node(declaration_struct_statement::from_ast(struct_decl));
			}
			case ast_statement_node::type_t::UnionDeclaration: {
				const auto& union_decl = std::get<ast_statement_union_declaration>(ast_stmt.value);
				return statement_node(declaration_union_statement::from_ast(union_decl));
			}
			case ast_statement_node::type_t::TypeDeclaration: {
				const auto& typedef_decl = std::get<ast_statement_type_declaration>(ast_stmt.value);
				return statement_node(declaration_typedef_statement::from_ast(typedef_decl));
			}
			case ast_statement_node::type_t::IfStatement: {
				const auto& if_stmt = std::get<ast_statement_if>(ast_stmt.value);
				return statement_node(if_statement::from_ast(if_stmt));
			}
			case ast_statement_node::type_t::WhileStatement: {
				const auto& while_stmt = std::get<ast_statement_while>(ast_stmt.value);
				return statement_node(while_statement::from_ast(while_stmt));
			}
			case ast_statement_node::type_t::ForStatement: {
				// for statements are treated as syntactic sugar for while statements
				const auto& for_stmt = std::get<ast_statement_for>(ast_stmt.value);
				if (for_stmt.body->type != ast_statement_node::type_t::BlockStatement) {
					throw std::runtime_error("For statement body must be a block");
				}
				expressions::expression_node condition;
				if (for_stmt.condition) {
					condition = expressions::expression_node::from_ast(*for_stmt.condition);
				}
				else {
					// no condition means 'true'
					condition = expressions::expression_node(
						expressions::expression_node::kind_t::LITERAL,
						expressions::literal_expression(expressions::literal_expression::kind_t::BOOL, true)
					);
				}
				block_statement body = block_statement::from_ast(std::get<ast_statement_block>(for_stmt.body->value));
				if (for_stmt.update) {
					// add update expression as last statement in body
					body.statements.push_back(std::make_shared<statement_node>(
						statement_node(expressions::expression_node::from_ast(*for_stmt.update))));
				}
				while_statement while_stmt(condition, body, false);
				// add surrounding block and initializer if present
				block_statement full_block;
				if (for_stmt.initializer) {
					full_block.statements.push_back(std::make_shared<statement_node>(
						statement_node::from_ast(*for_stmt.initializer)));
				}
				full_block.statements.push_back(std::make_shared<statement_node>(statement_node(while_stmt)));
				return statement_node(full_block);
			}
			case ast_statement_node::type_t::ReturnStatement: {
				const auto& return_stmt = std::get<ast_statement_return>(ast_stmt.value);
				return statement_node(return_statement::from_ast(return_stmt));
			}
			case ast_statement_node::type_t::ExpressionStatement: {
				const auto& expr_stmt = std::get<ast_statement_expression>(ast_stmt.value);
				return statement_node(
					expressions::expression_node::from_ast(*expr_stmt.expression));
			}
			case ast_statement_node::type_t::BlockStatement: {
				const auto& block_stmt = std::get<ast_statement_block>(ast_stmt.value);
				return statement_node(block_statement::from_ast(block_stmt));
			}
			case ast_statement_node::type_t::Unknown:
				throw std::runtime_error("Cannot convert unknown AST statement to analysis statement");
		}
		throw std::runtime_error("Unknown AST statement type");
	}
} // unqlang::analysis::statements
