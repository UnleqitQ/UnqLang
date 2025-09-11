#include "expressions.hpp"

namespace unqlang::analysis::expressions {
	types::type_node binary_expression::get_type(
		const variables::storage& storage,
		const functions::storage& func_storage,
		const types::type_system& type_sys
	) const {
		if (left == nullptr || right == nullptr) {
			throw std::runtime_error("Binary expression missing operand");
		}
		return type_sys.get_result_type_binary(
			op_to_ast(op),
			left->get_type(storage, func_storage, type_sys),
			right->get_type(storage, func_storage, type_sys)
		);
	}
	bool binary_expression::operator==(const binary_expression& other) const {
		if (op != other.op) {
			return false;
		}
		if ((left == nullptr) != (other.left == nullptr)) {
			return false;
		}
		if (left != nullptr && (*left != *other.left)) {
			return false;
		}
		if ((right == nullptr) != (other.right == nullptr)) {
			return false;
		}
		if (right != nullptr && *right != *other.right) {
			return false;
		}
		return true;
	}
	ast_expression_binary::type_t op_to_ast(binary_expression::operator_t op) {
		switch (op) {
			case binary_expression::operator_t::ADD:
				return ast_expression_binary::type_t::Add;
			case binary_expression::operator_t::SUB:
				return ast_expression_binary::type_t::Subtract;
			case binary_expression::operator_t::MUL:
				return ast_expression_binary::type_t::Multiply;
			case binary_expression::operator_t::DIV:
				return ast_expression_binary::type_t::Divide;
			case binary_expression::operator_t::MOD:
				return ast_expression_binary::type_t::Modulo;
			case binary_expression::operator_t::AND:
				return ast_expression_binary::type_t::BitwiseAnd;
			case binary_expression::operator_t::OR:
				return ast_expression_binary::type_t::BitwiseOr;
			case binary_expression::operator_t::XOR:
				return ast_expression_binary::type_t::BitwiseXor;
			case binary_expression::operator_t::SHL:
				return ast_expression_binary::type_t::ShiftLeft;
			case binary_expression::operator_t::SHR:
				return ast_expression_binary::type_t::ShiftRight;
			case binary_expression::operator_t::LAND:
				return ast_expression_binary::type_t::LogicalAnd;
			case binary_expression::operator_t::LOR:
				return ast_expression_binary::type_t::LogicalOr;
			case binary_expression::operator_t::EQ:
				return ast_expression_binary::type_t::Equal;
			case binary_expression::operator_t::NEQ:
				return ast_expression_binary::type_t::NotEqual;
			case binary_expression::operator_t::LT:
				return ast_expression_binary::type_t::Less;
			case binary_expression::operator_t::GT:
				return ast_expression_binary::type_t::Greater;
			case binary_expression::operator_t::LTE:
				return ast_expression_binary::type_t::LessEqual;
			case binary_expression::operator_t::GTE:
				return ast_expression_binary::type_t::GreaterEqual;
			case binary_expression::operator_t::ASSIGN:
				return ast_expression_binary::type_t::Assignment;
			case binary_expression::operator_t::ARRAY_SUBSCRIPT:
				return ast_expression_binary::type_t::ArraySubscript;
		}
		throw std::runtime_error("Unknown binary operator");
	}
	binary_expression::operator_t op_from_ast(ast_expression_binary::type_t op) {
		switch (op) {
			case ast_expression_binary::type_t::Add:
				return binary_expression::operator_t::ADD;
			case ast_expression_binary::type_t::Subtract:
				return binary_expression::operator_t::SUB;
			case ast_expression_binary::type_t::Multiply:
				return binary_expression::operator_t::MUL;
			case ast_expression_binary::type_t::Divide:
				return binary_expression::operator_t::DIV;
			case ast_expression_binary::type_t::Modulo:
				return binary_expression::operator_t::MOD;
			case ast_expression_binary::type_t::BitwiseAnd:
				return binary_expression::operator_t::AND;
			case ast_expression_binary::type_t::BitwiseOr:
				return binary_expression::operator_t::OR;
			case ast_expression_binary::type_t::BitwiseXor:
				return binary_expression::operator_t::XOR;
			case ast_expression_binary::type_t::ShiftLeft:
				return binary_expression::operator_t::SHL;
			case ast_expression_binary::type_t::ShiftRight:
				return binary_expression::operator_t::SHR;
			case ast_expression_binary::type_t::LogicalAnd:
				return binary_expression::operator_t::LAND;
			case ast_expression_binary::type_t::LogicalOr:
				return binary_expression::operator_t::LOR;
			case ast_expression_binary::type_t::Equal:
				return binary_expression::operator_t::EQ;
			case ast_expression_binary::type_t::NotEqual:
				return binary_expression::operator_t::NEQ;
			case ast_expression_binary::type_t::Less:
				return binary_expression::operator_t::LT;
			case ast_expression_binary::type_t::Greater:
				return binary_expression::operator_t::GT;
			case ast_expression_binary::type_t::LessEqual:
				return binary_expression::operator_t::LTE;
			case ast_expression_binary::type_t::GreaterEqual:
				return binary_expression::operator_t::GTE;
			case ast_expression_binary::type_t::Assignment:
				return binary_expression::operator_t::ASSIGN;
			case ast_expression_binary::type_t::ArraySubscript:
				return binary_expression::operator_t::ARRAY_SUBSCRIPT;
			case ast_expression_binary::type_t::Comma:
				throw std::runtime_error("Comma operator is not a valid binary operator in this context");
		}
		throw std::runtime_error("Unknown AST binary operator");
	}
	binary_expression binary_expression::from_ast(const ast_expression_binary& ast_bin) {
		return binary_expression(
			op_from_ast(ast_bin.type),
			std::make_shared<expression_node>(expression_node::from_ast(*ast_bin.left)),
			std::make_shared<expression_node>(expression_node::from_ast(*ast_bin.right))
		);
	}

	types::type_node unary_expression::get_type(
		const variables::storage& storage,
		const functions::storage& func_storage,
		const types::type_system& type_sys
	) const {
		if (operand == nullptr) {
			throw std::runtime_error("Unary expression missing operand");
		}
		return type_sys.get_result_type_unary(
			op_to_ast(op),
			operand->get_type(storage, func_storage, type_sys)
		);
	}
	bool unary_expression::operator==(const unary_expression& other) const {
		if (op != other.op) {
			return false;
		}
		if ((operand == nullptr) != (other.operand == nullptr)) {
			return false;
		}
		if (operand != nullptr && *operand != *other.operand) {
			return false;
		}
		return true;
	}
	unary_expression unary_expression::from_ast(const ast_expression_unary& ast_un) {
		return unary_expression(
			op_from_ast(ast_un.type),
			std::make_shared<expression_node>(expression_node::from_ast(*ast_un.operand))
		);
	}
	ast_expression_unary::type_t op_to_ast(unary_expression::operator_t op) {
		switch (op) {
			case unary_expression::operator_t::PLUS:
				return ast_expression_unary::type_t::Positive;
			case unary_expression::operator_t::MINUS:
				return ast_expression_unary::type_t::Negate;
			case unary_expression::operator_t::NOT:
				return ast_expression_unary::type_t::BitwiseNot;
			case unary_expression::operator_t::LNOT:
				return ast_expression_unary::type_t::LogicalNot;
			case unary_expression::operator_t::PRE_INC:
				return ast_expression_unary::type_t::PrefixIncrement;
			case unary_expression::operator_t::PRE_DEC:
				return ast_expression_unary::type_t::PrefixDecrement;
			case unary_expression::operator_t::POST_INC:
				return ast_expression_unary::type_t::PostfixIncrement;
			case unary_expression::operator_t::POST_DEC:
				return ast_expression_unary::type_t::PostfixDecrement;
			case unary_expression::operator_t::DEREFERENCE:
				return ast_expression_unary::type_t::Dereference;
			case unary_expression::operator_t::ADDRESS_OF:
				return ast_expression_unary::type_t::AddressOf;
			case unary_expression::operator_t::SIZEOF:
				return ast_expression_unary::type_t::SizeOf;
		}
		throw std::runtime_error("Unknown unary operator");
	}
	unary_expression::operator_t op_from_ast(ast_expression_unary::type_t op) {
		switch (op) {
			case ast_expression_unary::type_t::Positive:
				return unary_expression::operator_t::PLUS;
			case ast_expression_unary::type_t::Negate:
				return unary_expression::operator_t::MINUS;
			case ast_expression_unary::type_t::BitwiseNot:
				return unary_expression::operator_t::NOT;
			case ast_expression_unary::type_t::LogicalNot:
				return unary_expression::operator_t::LNOT;
			case ast_expression_unary::type_t::PrefixIncrement:
				return unary_expression::operator_t::PRE_INC;
			case ast_expression_unary::type_t::PrefixDecrement:
				return unary_expression::operator_t::PRE_DEC;
			case ast_expression_unary::type_t::PostfixIncrement:
				return unary_expression::operator_t::POST_INC;
			case ast_expression_unary::type_t::PostfixDecrement:
				return unary_expression::operator_t::POST_DEC;
			case ast_expression_unary::type_t::Dereference:
				return unary_expression::operator_t::DEREFERENCE;
			case ast_expression_unary::type_t::AddressOf:
				return unary_expression::operator_t::ADDRESS_OF;
			case ast_expression_unary::type_t::SizeOf:
				return unary_expression::operator_t::SIZEOF;
		}
		throw std::runtime_error("Unknown AST unary operator");
	}

	types::type_node call_expression::get_type(
		const variables::storage& storage,
		const functions::storage& func_storage,
		const types::type_system& type_sys
	) const {
		if (callee == nullptr) {
			throw std::runtime_error("Call expression missing callee");
		}

		types::function_type func_type;
		auto callee_type = callee->get_type(storage, func_storage, type_sys);
		if (callee_type.kind != types::type_node::kind_t::FUNCTION) {
			throw std::runtime_error("Callee is not a function type");
		}
		func_type = std::get<types::function_type>(callee_type.value);

		// check argument types
		if (func_type.parameter_types.size() != arguments.size()) {
			throw std::runtime_error("Function call argument count mismatch");
		}
		for (size_t i = 0; i < arguments.size(); i++) {
			if (arguments[i] == nullptr) {
				throw std::runtime_error("Call expression missing argument");
			}
			auto param_type = func_type.parameter_types[i];
			auto arg_type = arguments[i]->get_type(storage, func_storage, type_sys);
			auto resolved_param_type = type_sys.resolved_type(*param_type);
			auto resolved_arg_type = type_sys.resolved_type(arg_type);
			if (resolved_param_type.kind != resolved_arg_type.kind &&
				!(resolved_param_type.kind == types::type_node::kind_t::POINTER &&
					resolved_arg_type.kind == types::type_node::kind_t::ARRAY)) {
				throw std::runtime_error("Function call argument type mismatch");
			}
			if (resolved_arg_type.kind == types::type_node::kind_t::PRIMITIVE) {
				// check for implicit conversions
				if (!types::can_implicitly_convert(
					std::get<types::primitive_type>(resolved_arg_type.value),
					std::get<types::primitive_type>(resolved_param_type.value)
				)) {
					throw std::runtime_error("Function call argument type mismatch");
				}
				continue;
			}
			if (resolved_arg_type.kind == types::type_node::kind_t::POINTER) {
				// check for void ptr conversion
				auto arg_pointee = std::get<types::pointer_type>(resolved_arg_type.value).pointee_type;
				auto param_pointee = std::get<types::pointer_type>(resolved_param_type.value).pointee_type;
				auto resolved_param_pointee = type_sys.resolved_type(*param_pointee);
				if (resolved_param_pointee.kind == types::type_node::kind_t::PRIMITIVE &&
					std::get<types::primitive_type>(resolved_param_pointee.value) == types::primitive_type::VOID) {
					// void* can accept any pointer type
					continue;
				}
				if (type_sys.is_equivalent(*arg_pointee, *param_pointee)) {
					continue;
				}
				throw std::runtime_error("Function call argument type mismatch");
			}
			if (resolved_arg_type.kind == types::type_node::kind_t::ARRAY) {
				// array can decay to pointer
				auto arg_element = std::get<types::array_type>(resolved_arg_type.value).element_type;
				auto param_pointee = std::get<types::pointer_type>(resolved_param_type.value).pointee_type;
				// check for void* conversion
				auto resolved_param_pointee = type_sys.resolved_type(*param_pointee);
				if (resolved_param_pointee.kind == types::type_node::kind_t::PRIMITIVE &&
					std::get<types::primitive_type>(resolved_param_pointee.value) == types::primitive_type::VOID) {
					// void* can accept any pointer type
					continue;
				}
				// check element type match
				if (type_sys.is_equivalent(*arg_element, *param_pointee)) {
					continue;
				}
				throw std::runtime_error("Function call argument type mismatch");
			}
			// for other types, require exact match
			if (!type_sys.is_equivalent(resolved_arg_type, resolved_param_type)) {
				throw std::runtime_error("Function call argument type mismatch");
			}
		}
		// arguments match
		return *func_type.return_type;
	}
	bool call_expression::operator==(const call_expression& other) const {
		if ((callee == nullptr) != (other.callee == nullptr)) {
			return false;
		}
		if (callee != nullptr && *callee != *other.callee) {
			return false;
		}
		if (arguments.size() != other.arguments.size()) {
			return false;
		}
		for (size_t i = 0; i < arguments.size(); i++) {
			if ((arguments[i] == nullptr) != (other.arguments[i] == nullptr)) {
				return false;
			}
			if (arguments[i] != nullptr && *arguments[i] != *other.arguments[i]) {
				return false;
			}
		}
		return true;
	}
	call_expression call_expression::from_ast(const ast_expression_call& ast_call) {
		std::vector<std::shared_ptr<expression_node>> args;
		for (const auto& ast_arg : ast_call.arguments) {
			args.push_back(std::make_shared<expression_node>(expression_node::from_ast(*ast_arg)));
		}
		return call_expression(
			std::make_shared<expression_node>(expression_node::from_ast(*ast_call.callee)),
			std::move(args)
		);
	}

	types::type_node member_expression::get_type(
		const variables::storage& storage,
		const functions::storage& func_storage,
		const types::type_system& type_sys
	) const {
		if (object == nullptr) {
			throw std::runtime_error("Member expression missing object");
		}
		auto obj_type = object->get_type(storage, func_storage, type_sys);
		return type_sys.get_result_type_member_access(obj_type, member, pointer);
	}
	bool member_expression::operator==(const member_expression& other) const {
		if ((object == nullptr) != (other.object == nullptr)) {
			return false;
		}
		if (object != nullptr && *object != *other.object) {
			return false;
		}
		return member == other.member && pointer == other.pointer;
	}
	member_expression member_expression::from_ast(const ast_member_access& ast_mem) {
		return member_expression(
			std::make_shared<expression_node>(expression_node::from_ast(*ast_mem.object)),
			ast_mem.property,
			ast_mem.pointer
		);
	}

	types::type_node ternary_expression::get_type(
		const variables::storage& storage,
		const functions::storage& func_storage,
		const types::type_system& type_sys
	) const {
		if (condition == nullptr || then_branch == nullptr || else_branch == nullptr) {
			throw std::runtime_error("Ternary expression missing branch");
		}
		return type_sys.get_result_type_ternary(
			then_branch->get_type(storage, func_storage, type_sys),
			else_branch->get_type(storage, func_storage, type_sys)
		);
	}
	bool ternary_expression::operator==(const ternary_expression& other) const {
		if ((condition == nullptr) != (other.condition == nullptr)) {
			return false;
		}
		if (condition != nullptr && *condition != *other.condition) {
			return false;
		}
		if ((then_branch == nullptr) != (other.then_branch == nullptr)) {
			return false;
		}
		if (then_branch != nullptr && *then_branch != *other.then_branch) {
			return false;
		}
		if ((else_branch == nullptr) != (other.else_branch == nullptr)) {
			return false;
		}
		if (else_branch != nullptr && *else_branch != *other.else_branch) {
			return false;
		}
		return true;
	}
	ternary_expression ternary_expression::from_ast(const ast_expression_ternary& ast_ter) {
		return ternary_expression(
			std::make_shared<expression_node>(expression_node::from_ast(*ast_ter.condition)),
			std::make_shared<expression_node>(expression_node::from_ast(*ast_ter.then)),
			std::make_shared<expression_node>(expression_node::from_ast(*ast_ter.otherwise))
		);
	}
	expression_node expression_node::from_ast(const ast_expression_node& ast_expr) {
		switch (ast_expr.type) {
			case ast_expression_node::type_t::Literal:
				return literal_expression::from_ast(std::get<ast_expression_literal>(ast_expr.value));
			case ast_expression_node::type_t::Identifier:
				return identifier_expression(std::get<std::string>(ast_expr.value));
			case ast_expression_node::type_t::Binary:
				return binary_expression::from_ast(std::get<ast_expression_binary>(ast_expr.value));
			case ast_expression_node::type_t::Unary:
				return unary_expression::from_ast(std::get<ast_expression_unary>(ast_expr.value));
			case ast_expression_node::type_t::FunctionCall:
				return call_expression::from_ast(std::get<ast_expression_call>(ast_expr.value));
			case ast_expression_node::type_t::MemberAccess:
				return member_expression::from_ast(std::get<ast_member_access>(ast_expr.value));
			case ast_expression_node::type_t::Ternary:
				return ternary_expression::from_ast(std::get<ast_expression_ternary>(ast_expr.value));
			case ast_expression_node::type_t::Unknown:
				throw std::runtime_error("Cannot convert unknown AST expression to analysis expression");
		}
		throw std::runtime_error("Unknown AST expression kind");
	}
} // unqlang::analysis::expressions
