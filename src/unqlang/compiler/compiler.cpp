#include "compiler.hpp"

#include <ranges>

namespace unqlang::compiler {
	regmask get_containing_regs(const assembly::assembly_memory& mem) {
		regmask mask;
		switch (mem.memory_type) {
			case assembly::assembly_memory::type::REGISTER:
				mask.set(std::get<machine::register_t>(mem.value).id, true);
				break;
			case assembly::assembly_memory::type::DISPLACEMENT:
				mask.set(std::get<assembly::assembly_memory::displacement>(mem.value).reg.id, true);
				break;
			case assembly::assembly_memory::type::SCALED_INDEX: {
				auto si = std::get<assembly::assembly_memory::scaled_index>(mem.value);
				mask.set(si.base.id, true);
				mask.set(si.index.id, true);
				break;
			}
			case assembly::assembly_memory::type::SCALED_INDEX_DISPLACEMENT: {
				auto sid = std::get<assembly::assembly_memory::scaled_index_displacement>(mem.value);
				mask.set(sid.base.id, true);
				mask.set(sid.index.id, true);
				break;
			}
			case assembly::assembly_memory::type::DIRECT:
				// no registers
				break;
		}
		return mask;
	}

	machine::register_id find_free_register(
		regmask used_regs,
		std::vector<machine::register_id> order,
		regmask ban = {}
	) {
		std::optional<machine::register_id> first_allowed;
		for (const auto r : order) {
			if (ban.get(r)) {
				continue;
			}
			if (!first_allowed.has_value()) {
				first_allowed = r;
			}
			if (!used_regs.get(r)) {
				return r;
			}
		}
		// all registers are used, return the first allowed one
		if (first_allowed.has_value()) {
			return first_allowed.value();
		}
		throw std::runtime_error("No registers available");
	}

	machine::register_id find_free_register(
		regmask used_regs,
		std::vector<machine::register_id> order,
		std::initializer_list<machine::register_id> ban_list
	) {
		std::optional<machine::register_id> first_allowed;
		for (const auto r : order) {
			if (std::ranges::find(ban_list, r) != ban_list.end()) {
				continue;
			}
			if (!first_allowed.has_value()) {
				first_allowed = r;
			}
			if (!used_regs.get(r)) {
				return r;
			}
		}
		// all registers are used, return the first allowed one
		if (first_allowed.has_value()) {
			return first_allowed.value();
		}
		throw std::runtime_error("No registers available");
	}

	std::string generate_function_label(
		const std::string& name
	) {
		// Currently ignoring parameters
		std::string fname = std::format("func_{}_entry", name);
		return fname;
	}

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
	) {
		auto resolved_dest_type = context.global_context->type_system->resolved_type(dest_type);
		regmask dest_regs = get_containing_regs(dest);
		auto src_type = src.get_type(
			*context.variable_storage,
			*context.global_context->function_storage,
			*context.global_context->type_system
		);
		auto resolved_src_type = context.global_context->type_system->resolved_type(src_type);
		// we can assume the types are compatible (checked during semantic analysis)
		if (resolved_dest_type.kind == analysis::types::type_node::kind_t::PRIMITIVE &&
			resolved_src_type.kind == analysis::types::type_node::kind_t::PRIMITIVE) {
			// find a free register or use eax (order to check: eax, ecx, edx, ebx)
			machine::register_id target_reg = find_free_register(
				used_regs,
				{machine::register_id::eax, machine::register_id::ecx, machine::register_id::edx, machine::register_id::ebx},
				dest_regs
			);
			modified_regs.set(target_reg, true);
			compile_primitive_expression(
				src, context, program, current_scope,
				target_reg, used_regs | dest_regs, modified_regs, statement_index
			);
			// move the value from the register to the destination
			auto dtp = std::get<analysis::types::primitive_type>(resolved_dest_type.value);
			auto stp = std::get<analysis::types::primitive_type>(resolved_src_type.value);
			switch (dtp) {
				case analysis::types::primitive_type::VOID:
					throw std::runtime_error("Cannot assign to void type");
				case analysis::types::primitive_type::BOOL: {
					if (stp != analysis::types::primitive_type::BOOL) {
						// need to convert to bool
						// compare the register to 0 and set to 1 if not equal, else 0
						switch (stp) {
							case analysis::types::primitive_type::SIGNED_CHAR:
							case analysis::types::primitive_type::UNSIGNED_CHAR:
								program.push_back(assembly::assembly_instruction(
									machine::operation::CMP,
									assembly::assembly_operand({target_reg, machine::register_access::low_byte}),
									assembly::assembly_operand(0)
								));
								break;
							case analysis::types::primitive_type::SIGNED_SHORT:
							case analysis::types::primitive_type::UNSIGNED_SHORT:
								program.push_back(assembly::assembly_instruction(
									machine::operation::CMP,
									assembly::assembly_operand({target_reg, machine::register_access::word}),
									assembly::assembly_operand(0)
								));
								break;
							case analysis::types::primitive_type::SIGNED_INT:
							case analysis::types::primitive_type::UNSIGNED_INT:
								program.push_back(assembly::assembly_instruction(
									machine::operation::CMP,
									assembly::assembly_operand({target_reg, machine::register_access::dword}),
									assembly::assembly_operand(0)
								));
								break;
							default:
								throw std::runtime_error("Cannot convert this type to bool");
						}
						program.push_back(assembly::assembly_instruction(
							machine::operation::SETNZ,
							assembly::assembly_result({machine::data_size_t::BYTE, dest})
						));
						break;
					}
				}
				case analysis::types::primitive_type::SIGNED_CHAR:
				case analysis::types::primitive_type::UNSIGNED_CHAR:
					program.push_back(assembly::assembly_instruction(
						machine::operation::MOV,
						assembly::assembly_result(assembly::assembly_memory_pointer(machine::data_size_t::BYTE, dest)),
						assembly::assembly_operand({target_reg, machine::register_access::low_byte})
					));
					break;
				case analysis::types::primitive_type::SIGNED_SHORT:
				case analysis::types::primitive_type::UNSIGNED_SHORT:
					program.push_back(assembly::assembly_instruction(
						machine::operation::MOV,
						assembly::assembly_result(assembly::assembly_memory_pointer(machine::data_size_t::WORD, dest)),
						assembly::assembly_operand({target_reg, machine::register_access::word})
					));
				case analysis::types::primitive_type::UNSIGNED_INT:
				case analysis::types::primitive_type::SIGNED_INT:
					program.push_back(assembly::assembly_instruction(
						machine::operation::MOV,
						assembly::assembly_result(assembly::assembly_memory_pointer(machine::data_size_t::DWORD, dest)),
						assembly::assembly_operand({target_reg, machine::register_access::dword})
					));
					break;
				default:
					throw std::runtime_error("Assignment for this primitive type not implemented yet");
			}
			return;
		}
		if (resolved_src_type.kind == analysis::types::type_node::kind_t::POINTER &&
			resolved_dest_type.kind == analysis::types::type_node::kind_t::POINTER) {
			// pointer assignment, just treat as uint32
			// find a free register or use eax (order to check: eax, ecx, edx, ebx)
			machine::register_id target_reg = find_free_register(
				used_regs,
				{machine::register_id::eax, machine::register_id::ecx, machine::register_id::edx, machine::register_id::ebx},
				dest_regs
			);
			modified_regs.set(target_reg, true);
			compile_primitive_expression(
				src, context, program, current_scope,
				target_reg, used_regs | dest_regs, modified_regs, statement_index
			);
			program.push_back(assembly::assembly_instruction(
				machine::operation::MOV,
				assembly::assembly_result(assembly::assembly_memory_pointer(machine::data_size_t::DWORD, dest)),
				assembly::assembly_operand({target_reg, machine::register_access::dword})
			));
			return;
		}
		if (resolved_dest_type.kind == analysis::types::type_node::kind_t::POINTER &&
			resolved_src_type.kind == analysis::types::type_node::kind_t::ARRAY) {
			// array to pointer decay, just get the address of the array
			assembly::assembly_program_t temp_program;
			auto addr = compile_reference(
				src, context, temp_program, current_scope,
				used_regs | dest_regs, modified_regs, statement_index
			);
			regmask addr_regs = get_containing_regs(addr);
			if ((addr_regs & dest_regs).raw == 0) {
				regmask overlap = used_regs & addr_regs;
				if (overlap.raw == 0) {
					// no overlap, we can just append the temp program
					program.insert(program.end(), temp_program.begin(), temp_program.end());
					// and move the address to the destination
					program.push_back(assembly::assembly_instruction(
						machine::operation::LEA,
						assembly::assembly_result(assembly::assembly_memory_pointer(machine::data_size_t::DWORD, dest)),
						addr
					));
					return;
				}
				// overlap, need to save/restore the overlapping registers
				std::vector<machine::register_id> to_save;
				for (const auto r : regmask::USABLE_REGISTERS) {
					if (overlap.get(r)) {
						program.push_back(assembly::assembly_instruction(
							machine::operation::PUSH,
							assembly::assembly_operand({r, machine::register_access::dword})
						));
						to_save.push_back(r);
					}
				}
				// append the temp program
				program.insert(program.end(), temp_program.begin(), temp_program.end());
				// move the address to the destination
				program.push_back(assembly::assembly_instruction(
					machine::operation::LEA,
					assembly::assembly_result(assembly::assembly_memory_pointer(machine::data_size_t::DWORD, dest)),
					addr
				));
				// restore the saved registers in reverse order
				for (auto it = to_save.rbegin(); it != to_save.rend(); ++it) {
					program.push_back(assembly::assembly_instruction(
						machine::operation::POP,
						assembly::assembly_operand({*it, machine::register_access::dword})
					));
				}
			}
			// overlap between addr and dest (annoying case)
			// need to use a temporary register to hold the address
			machine::register_id temp_reg = find_free_register(
				used_regs,
				{machine::register_id::eax, machine::register_id::ecx, machine::register_id::edx, machine::register_id::ebx},
				dest_regs
			);
			modified_regs.set(temp_reg, true);
			std::vector<machine::register_id> to_save;
			std::vector<machine::register_id> to_save_dest;
			for (const auto r : regmask::USABLE_REGISTERS) {
				if (!addr_regs.get(r) && r != temp_reg)
					continue;
				if (dest_regs.get(r))
					to_save_dest.push_back(r);
				else if (used_regs.get(r))
					to_save.push_back(r);
			}
			// save registers in to_save
			for (const auto r : to_save) {
				program.push_back(assembly::assembly_instruction(
					machine::operation::PUSH,
					assembly::assembly_operand({r, machine::register_access::dword})
				));
			}
			// save registers in to_save_dest
			for (const auto r : to_save_dest) {
				program.push_back(assembly::assembly_instruction(
					machine::operation::PUSH,
					assembly::assembly_operand({r, machine::register_access::dword})
				));
			}
			// append the temp program
			program.insert(program.end(), temp_program.begin(), temp_program.end());
			// move the address to the temp register
			program.push_back(assembly::assembly_instruction(
				machine::operation::LEA,
				assembly::assembly_result({temp_reg, machine::register_access::dword}),
				addr
			));
			// restore registers in to_save_dest in reverse order
			for (auto it = to_save_dest.rbegin(); it != to_save_dest.rend(); ++it) {
				program.push_back(assembly::assembly_instruction(
					machine::operation::POP,
					assembly::assembly_operand({*it, machine::register_access::dword})
				));
			}
			// move the address from the temp register to the destination
			program.push_back(assembly::assembly_instruction(
				machine::operation::MOV,
				assembly::assembly_result(assembly::assembly_memory_pointer(machine::data_size_t::DWORD, dest)),
				assembly::assembly_operand({temp_reg, machine::register_access::dword})
			));
			// restore registers in to_save in reverse order
			for (auto it = to_save.rbegin(); it != to_save.rend(); ++it) {
				program.push_back(assembly::assembly_instruction(
					machine::operation::POP,
					assembly::assembly_operand({*it, machine::register_access::dword})
				));
			}
			return;
		}
		throw std::runtime_error("Assignment for these types not implemented yet");
	}

	assembly::assembly_memory compile_reference(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index
	) {
		switch (expr.kind) {
			case analysis::expressions::expression_node::kind_t::LITERAL:
				throw std::runtime_error("Cannot take reference of a literal");
			case analysis::expressions::expression_node::kind_t::IDENTIFIER: {
				// Checks whether the identifier is a variable or a function
				// If it's a variable, return its memory pointer
				// If it's a (global) function, return its address as a memory pointer
				// (that's not the case for variables containing function pointers, they are treated as normal variables)
				// If neither, throw an error
				const auto& ident = std::get<analysis::expressions::identifier_expression>(expr.value);
				if (context.variable_storage->is_variable_declared(ident.name)) {
					const auto declaring_scope = context.variable_storage->get_declaring_scope(ident.name);
					const auto var_info = declaring_scope->get_variable(ident.name, false);
					switch (declaring_scope->storage_type) {
						case analysis::variables::storage::storage_type_t::Global:
							throw std::runtime_error("Taking reference of global variables is not supported yet");
						case analysis::variables::storage::storage_type_t::Function: {
							// Variable is a parameter passed to the function
							auto func_sig = context.current_function_signature;
							if (func_sig == nullptr) {
								throw std::runtime_error("Current function signature is null");
							}
							// find the parameter index
							uint32_t idx = func_sig->name_index_map.at(ident.name);
							auto param = func_sig->parameters[idx];
							uint32_t offset = param.offset;
							return assembly::assembly_memory(
								machine::register_t{machine::register_id::ebp},
								static_cast<int32_t>(offset)
							);
						}
						case analysis::variables::storage::storage_type_t::Block: {
							// Variable is a local variable
							auto var = current_scope.get_variable(ident.name, true);
							// offset is negative from ebp
							return assembly::assembly_memory(
								machine::register_t{machine::register_id::ebp},
								-static_cast<int32_t>(var.offset)
							);
						}
					}
					throw std::runtime_error("Unknown variable storage type");
				}
				if (context.global_context->function_storage->is_function_declared(ident.name)) {
					const auto func_info = context.global_context->function_storage->get_function(ident.name);
					// generate the label for the function
					const auto label = generate_function_label(func_info.name);
					return assembly::assembly_memory(label);
				}
				throw std::runtime_error("Identifier not found: " + ident.name);
			}
			case analysis::expressions::expression_node::kind_t::UNARY: {
				// only dereference and pre-increment/decrement are allowed
				const auto& unary = std::get<analysis::expressions::unary_expression>(expr.value);
				if (unary.op == analysis::expressions::unary_expression::operator_t::PRE_INC ||
					unary.op == analysis::expressions::unary_expression::operator_t::PRE_DEC) {
					// we need to get the reference of the inner expression first
					auto inner_ref = compile_reference(
						*unary.operand, context, program,
						current_scope, used_regs, modified_regs, statement_index
					);
					// then we just do a normal increment/decrement on that memory
					auto inner_type = unary.operand->get_type(
						*context.variable_storage,
						*context.global_context->function_storage,
						*context.global_context->type_system
					);
					auto resolved_inner_type = context.global_context->type_system->resolved_type(inner_type);
					if (resolved_inner_type.kind != analysis::types::type_node::kind_t::PRIMITIVE &&
						resolved_inner_type.kind != analysis::types::type_node::kind_t::POINTER) {
						throw std::runtime_error("Can only increment/decrement primitive or pointer types");
					}
					machine::data_size_t data_size;
					if (resolved_inner_type.kind == analysis::types::type_node::kind_t::PRIMITIVE) {
						auto prim_type = std::get<analysis::types::primitive_type>(resolved_inner_type.value);
						data_size = analysis::types::to_data_size(prim_type);
					}
					else {
						// POINTER
						data_size = machine::data_size_t::DWORD;
					}
					// increment/decrement the memory directly
					program.push_back(assembly::assembly_instruction(
						unary.op == analysis::expressions::unary_expression::operator_t::PRE_INC
						? machine::operation::INC
						: machine::operation::DEC,
						assembly::assembly_result({data_size, inner_ref})
					));
					// return the memory reference
					return inner_ref;
				}
				if (unary.op != analysis::expressions::unary_expression::operator_t::DEREFERENCE)
					throw std::runtime_error("Only dereference and pre-increment/decrement are allowed for references");
				// compile the inner expression to a register
				// find a free register or use eax (order to check: eax, ecx, edx, ebx)
				machine::register_id addr_reg = find_free_register(
					used_regs,
					{machine::register_id::eax, machine::register_id::ecx, machine::register_id::edx, machine::register_id::ebx}
				);
				modified_regs.set(addr_reg, true);
				used_regs.set(addr_reg, true);
				compile_primitive_expression(
					*unary.operand, context, program,
					current_scope, addr_reg, used_regs, modified_regs, statement_index
				);
				// return memory at that address
				return assembly::assembly_memory(addr_reg);
			}
			case analysis::expressions::expression_node::kind_t::BINARY: {
				// this must be an assignment, pointer arithmetic or array subscript (pointer arithmetic is skipped for now)
				// TODO: implement pointer arithmetic
				const auto& binary = std::get<analysis::expressions::binary_expression>(expr.value);
				switch (binary.op) {
					case analysis::expressions::binary_expression::operator_t::ARRAY_SUBSCRIPT: {
						// get types of left and right
						auto left_type = binary.left->get_type(
							*context.variable_storage,
							*context.global_context->function_storage,
							*context.global_context->type_system
						);
						auto resolved_left_type = context.global_context->type_system->resolved_type(left_type);
						auto right_type = binary.right->get_type(
							*context.variable_storage,
							*context.global_context->function_storage,
							*context.global_context->type_system
						);
						auto resolved_right_type = context.global_context->type_system->resolved_type(right_type);
						// left side must be an array or pointer
						if (resolved_left_type.kind != analysis::types::type_node::kind_t::POINTER &&
							resolved_left_type.kind != analysis::types::type_node::kind_t::ARRAY) {
							throw std::runtime_error("Left side of array subscript must be an array or pointer");
						}
						uint32_t element_size;
						if (resolved_left_type.kind == analysis::types::type_node::kind_t::POINTER) {
							auto ptr_type = std::get<analysis::types::pointer_type>(resolved_left_type.value);
							element_size = context.global_context->type_system->get_type_size(*ptr_type.pointee_type);
						}
						else {
							// ARRAY
							auto arr_type = std::get<analysis::types::array_type>(resolved_left_type.value);
							element_size = context.global_context->type_system->get_type_size(*arr_type.element_type);
						}
						// right side must be an integer type
						if (resolved_right_type.kind != analysis::types::type_node::kind_t::PRIMITIVE ||
							!analysis::types::is_integral_type(
								std::get<analysis::types::primitive_type>(resolved_right_type.value))) {
							throw std::runtime_error("Right side of array subscript must be an integer type");
						}
						if (binary.right->kind == analysis::expressions::expression_node::kind_t::LITERAL) {
							// if the index is a literal, we can optimize the calculation
							const auto& lit = std::get<analysis::expressions::literal_expression>(binary.right->value);
							// no need to check type again, already done above
							int32_t index = std::get<int32_t>(lit.value);
							// get reference to left side
							auto left_ref = compile_reference(
								*binary.left, context, program,
								current_scope, used_regs, modified_regs, statement_index
							);
							// calculate address with offset
							int32_t offset = index * static_cast<int32_t>(element_size);
							switch (left_ref.memory_type) {
								case assembly::assembly_memory::type::DIRECT: {
									// direct memory access, just add offset to address
									auto val = std::get<assembly::extended_assembly_literal>(left_ref.value);
									return assembly::assembly_memory(
										assembly::extended_assembly_literal(
											assembly::extended_assembly_literal::type_t::ADD,
											std::make_shared<assembly::extended_assembly_literal>(val),
											std::make_shared<assembly::extended_assembly_literal>(
												assembly::assembly_literal(offset)
											)
										)
									);
								}
								case assembly::assembly_memory::type::REGISTER: {
									// register, create displacement
									auto reg = std::get<machine::register_t>(left_ref.value);
									return assembly::assembly_memory(reg, offset);
								}
								case assembly::assembly_memory::type::DISPLACEMENT: {
									// displacement, add to existing displacement
									auto disp = std::get<assembly::assembly_memory::displacement>(left_ref.value);
									return assembly::assembly_memory(
										disp.reg,
										assembly::extended_assembly_literal(
											assembly::extended_assembly_literal::type_t::ADD,
											std::make_shared<assembly::extended_assembly_literal>(disp.disp),
											std::make_shared<assembly::extended_assembly_literal>(
												assembly::assembly_literal(offset)
											)
										)
									);
								}
								case assembly::assembly_memory::type::SCALED_INDEX: {
									// scaled index, add to existing displacement
									auto si = std::get<assembly::assembly_memory::scaled_index>(left_ref.value);
									return assembly::assembly_memory(
										si.base,
										si.index,
										si.scale,
										assembly::assembly_literal(offset)
									);
								}
								case assembly::assembly_memory::type::SCALED_INDEX_DISPLACEMENT: {
									// scaled index with displacement, add to existing displacement
									auto sid = std::get<assembly::assembly_memory::scaled_index_displacement>(left_ref.value);
									return assembly::assembly_memory(
										sid.base,
										sid.index,
										sid.scale,
										assembly::extended_assembly_literal(
											assembly::extended_assembly_literal::type_t::ADD,
											std::make_shared<assembly::extended_assembly_literal>(sid.disp),
											std::make_shared<assembly::extended_assembly_literal>(
												assembly::assembly_literal(offset)
											)
										)
									);
								}
							}
						}
						// compile right side to a register
						// find a free register or use ebx (order to check: ebx, ecx, eax, edx)
						machine::register_id index_reg = find_free_register(
							used_regs,
							{
								machine::register_id::ebx, machine::register_id::ecx, machine::register_id::eax,
								machine::register_id::edx
							}
						);
						modified_regs.set(index_reg, true);
						used_regs.set(index_reg, true);
						// compile right side expression into index_reg
						compile_primitive_expression(
							*binary.right, context, program,
							current_scope, index_reg, used_regs, modified_regs, statement_index
						);
						// store program in temporary program to not mess up the register usage
						// (since we might need to save/restore registers below)
						assembly::assembly_program_t temp_program;
						auto val_mem = compile_reference(
							*binary.left, context, temp_program,
							current_scope, used_regs, modified_regs, statement_index
						);
						// if the value memory address contains the index register, we need to do some tricks
						regmask val_mem_regs = get_containing_regs(val_mem);
						// whether we need to save the address in a different register first
						bool needs_additional_save = false;
						if (val_mem_regs.get(index_reg))
							needs_additional_save = true;
						if (val_mem.memory_type == assembly::assembly_memory::type::SCALED_INDEX ||
							val_mem.memory_type == assembly::assembly_memory::type::SCALED_INDEX_DISPLACEMENT)
							needs_additional_save = true;

						if (needs_additional_save) {
							// this means, we need to save the address in a different register first using a LEA
							// find a free register or use eax (order to check: eax, ecx, edx, ebx)
							machine::register_id base_reg = find_free_register(
								used_regs,
								{
									machine::register_id::eax, machine::register_id::ecx, machine::register_id::edx,
									machine::register_id::ebx
								}
							);
							modified_regs.set(base_reg, true);
							used_regs.set(base_reg, true);
							// save the registers that are used in val_mem (except base_reg)
							regmask to_save = val_mem_regs & used_regs;
							to_save.set(base_reg, false);
							std::vector<machine::register_t> saved_regs;
							for (const auto r : regmask::USABLE_REGISTERS) {
								if (to_save.get(r)) {
									program.emplace_back(assembly::assembly_instruction(
										machine::operation::PUSH,
										assembly::assembly_operand{r}
									));
									saved_regs.emplace_back(r);
								}
							}
							// insert the temp program now
							program.insert(program.end(), temp_program.begin(), temp_program.end());
							temp_program.clear();
							// LEA the address into base_reg
							program.emplace_back(assembly::assembly_instruction(
								machine::operation::LEA,
								assembly::assembly_result{base_reg},
								val_mem
							));
							// now restore the saved registers
							for (auto it = saved_regs.rbegin(); it != saved_regs.rend(); ++it) {
								program.emplace_back(assembly::assembly_instruction(
									machine::operation::POP,
									assembly::assembly_result{*it}
								));
							}
							// now we have a scaled index with base_reg as base
							return assembly::assembly_memory(
								base_reg,
								index_reg,
								static_cast<int16_t>(element_size)
							);
						}
						// we have no conflicts (at least none to solve here), just insert the temp program
						program.insert(program.end(), temp_program.begin(), temp_program.end());
						// now we can return the memory
						switch (val_mem.memory_type) {
							case assembly::assembly_memory::type::DIRECT: {
								auto val = std::get<assembly::extended_assembly_literal>(val_mem.value);
								if (element_size == 1) {
									// simple displacement
									return assembly::assembly_memory(
										index_reg,
										val
									);
								}
								// scaled index with displacement
								return assembly::assembly_memory(
									index_reg,
									index_reg,
									static_cast<int16_t>(element_size - 1), // seems weird, but this is done because the base also adds 1
									val
								);
							}
							case assembly::assembly_memory::type::REGISTER: {
								// register, create scaled index
								auto reg = std::get<machine::register_t>(val_mem.value);
								return assembly::assembly_memory(
									reg,
									index_reg,
									static_cast<int16_t>(element_size)
								);
							}
							case assembly::assembly_memory::type::DISPLACEMENT: {
								// displacement, create scaled index with displacement
								auto disp = std::get<assembly::assembly_memory::displacement>(val_mem.value);
								return assembly::assembly_memory(
									disp.reg,
									index_reg,
									static_cast<int16_t>(element_size),
									disp.disp
								);
							}
							case assembly::assembly_memory::type::SCALED_INDEX:
							case assembly::assembly_memory::type::SCALED_INDEX_DISPLACEMENT:
								throw std::runtime_error(
									"Internal error: Should have been handled above (scaled index in array subscript)"
								);
						}
					}
					case analysis::expressions::binary_expression::operator_t::ASSIGN: {
						// left side must be a reference
						auto left_ref = compile_reference(
							*binary.left, context, program,
							current_scope, used_regs, modified_regs, statement_index
						);
						// assign the right side to the left side
						compile_assignment(
							left_ref,
							binary.left->get_type(
								*context.variable_storage,
								*context.global_context->function_storage,
								*context.global_context->type_system
							),
							*binary.right,
							context,
							program,
							current_scope,
							used_regs,
							modified_regs,
							statement_index
						);
						// return the left side reference
						return left_ref;
					}
					default:
						throw std::runtime_error("Only assignment operator or array subscript are supported for references");
				}
			}
			case analysis::expressions::expression_node::kind_t::MEMBER: {
				const auto& member_access = std::get<analysis::expressions::member_expression>(expr.value);
				// get the type of the object
				auto base_object_type = member_access.object->get_type(
					*context.variable_storage,
					*context.global_context->function_storage,
					*context.global_context->type_system
				);
				auto resolved_base_object_type = context.global_context->type_system->resolved_type(base_object_type);
				analysis::types::type_node object_type;
				if (member_access.pointer) {
					if (resolved_base_object_type.kind != analysis::types::type_node::kind_t::POINTER) {
						throw std::runtime_error("Base object of pointer member access must be a pointer");
					}
					auto ptr_type = std::get<analysis::types::pointer_type>(resolved_base_object_type.value);
					object_type = context.global_context->type_system->resolved_type(*ptr_type.pointee_type);
				}
				else
					object_type = resolved_base_object_type;
				if (object_type.kind != analysis::types::type_node::kind_t::STRUCT &&
					object_type.kind != analysis::types::type_node::kind_t::UNION) {
					throw std::runtime_error("Base object of member access must be a struct or union");
				}
				// if it is a union, just return the base object reference
				if (object_type.kind == analysis::types::type_node::kind_t::UNION) {
					return compile_reference(
						*member_access.object, context, program,
						current_scope, used_regs, modified_regs, statement_index
					);
				}
				// get the struct type
				auto struct_type = std::get<analysis::types::struct_type>(object_type.value);
				// find the member
				auto member_info =
					context.global_context->type_system->get_struct_member_info(struct_type, member_access.member);
				// get reference to base object
				auto base_ref = compile_reference(
					*member_access.object, context, program,
					current_scope, used_regs, modified_regs, statement_index
				);
				switch (base_ref.memory_type) {
					case assembly::assembly_memory::type::DIRECT: {
						// direct memory access, just add offset to address
						auto val = std::get<assembly::extended_assembly_literal>(base_ref.value);
						return assembly::assembly_memory(
							assembly::extended_assembly_literal(
								assembly::extended_assembly_literal::type_t::ADD,
								std::make_shared<assembly::extended_assembly_literal>(val),
								std::make_shared<assembly::extended_assembly_literal>(
									assembly::assembly_literal(static_cast<int32_t>(member_info.offset))
								)
							)
						);
					}
					case assembly::assembly_memory::type::REGISTER: {
						// register, create displacement
						auto reg = std::get<machine::register_t>(base_ref.value);
						return assembly::assembly_memory(
							reg,
							static_cast<int32_t>(member_info.offset)
						);
					}
					case assembly::assembly_memory::type::DISPLACEMENT: {
						// displacement, add to existing displacement
						auto disp = std::get<assembly::assembly_memory::displacement>(base_ref.value);
						return assembly::assembly_memory(
							disp.reg,
							assembly::extended_assembly_literal(
								assembly::extended_assembly_literal::type_t::ADD,
								std::make_shared<assembly::extended_assembly_literal>(disp.disp),
								std::make_shared<assembly::extended_assembly_literal>(
									assembly::assembly_literal(static_cast<int32_t>(member_info.offset))
								)
							)
						);
					}
					case assembly::assembly_memory::type::SCALED_INDEX: {
						// scaled index, add to existing displacement
						auto si = std::get<assembly::assembly_memory::scaled_index>(base_ref.value);
						return assembly::assembly_memory(
							si.base,
							si.index,
							si.scale,
							assembly::assembly_literal(static_cast<int32_t>(member_info.offset))
						);
					}
					case assembly::assembly_memory::type::SCALED_INDEX_DISPLACEMENT: {
						// scaled index with displacement, add to existing displacement
						auto sid = std::get<assembly::assembly_memory::scaled_index_displacement>(base_ref.value);
						return assembly::assembly_memory(
							sid.base,
							sid.index,
							sid.scale,
							assembly::extended_assembly_literal(
								assembly::extended_assembly_literal::type_t::ADD,
								std::make_shared<assembly::extended_assembly_literal>(sid.disp),
								std::make_shared<assembly::extended_assembly_literal>(
									assembly::assembly_literal(static_cast<int32_t>(member_info.offset))
								)
							)
						);
					}
				}
				throw std::runtime_error("Unknown memory type in member access");
			}
			default:
				break;
		}
		throw std::runtime_error("Unsupported expression type for reference");
	}

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
	) {
		if (left_type.kind != analysis::types::type_node::kind_t::PRIMITIVE ||
			right_type.kind != analysis::types::type_node::kind_t::PRIMITIVE) {
			throw std::runtime_error("Boolean binary expressions only support primitive types");
		}
		auto left_prim_type = std::get<analysis::types::primitive_type>(left_type.value);
		auto right_prim_type = std::get<analysis::types::primitive_type>(right_type.value);
		// comparisons
		if (binary.op == analysis::expressions::binary_expression::operator_t::EQ ||
			binary.op == analysis::expressions::binary_expression::operator_t::NEQ ||
			binary.op == analysis::expressions::binary_expression::operator_t::LT ||
			binary.op == analysis::expressions::binary_expression::operator_t::LTE ||
			binary.op == analysis::expressions::binary_expression::operator_t::GT ||
			binary.op == analysis::expressions::binary_expression::operator_t::GTE) {
			// find a free register (order to check: edx, ebx, ecx, eax)
			machine::register_id right_reg = find_free_register(
				used_regs,
				{machine::register_id::edx, machine::register_id::ebx, machine::register_id::ecx, machine::register_id::eax},
				{target_reg.id}
			);
			modified_regs.set(right_reg, true);
			used_regs.set(target_reg.id, false);
			bool right_is_used = used_regs.get(right_reg);
			if (right_is_used) {
				// need to save right_reg
				program.push_back(assembly::assembly_instruction(
					machine::operation::PUSH,
					assembly::assembly_operand({right_reg, machine::register_access::dword})
				));
			}
			used_regs.set(right_reg, false);

			machine::register_t right_reg_t{right_reg, analysis::types::to_data_size(right_prim_type)};
			machine::register_id left_reg = target_reg.id;
			machine::register_t left_reg_t{left_reg, analysis::types::to_data_size(left_prim_type)};

			// compile left and right expressions
			compile_primitive_expression(
				*binary.left, context, program, current_scope,
				left_reg_t, used_regs, modified_regs, statement_index
			);
			used_regs.set(target_reg.id, true);
			compile_primitive_expression(
				*binary.right, context, program, current_scope,
				right_reg_t, used_regs, modified_regs, statement_index
			);

			// get the bigger size
			machine::data_size_t cmp_size = std::max(
				analysis::types::to_data_size(left_prim_type),
				analysis::types::to_data_size(right_prim_type)
			);
			bool signed_comparison = analysis::types::is_signed_integral_type(left_prim_type) &&
				analysis::types::is_signed_integral_type(right_prim_type);
			// if sizes differ, need to extend the smaller one
			if (analysis::types::to_data_size(left_prim_type) != cmp_size) {
				// extend left
				program.push_back(assembly::assembly_instruction(
					signed_comparison ? machine::operation::MOVSX : machine::operation::MOVZX,
					assembly::assembly_result({left_reg, cmp_size}),
					assembly::assembly_operand({left_reg, analysis::types::to_data_size(left_prim_type)})
				));
				left_reg_t = {left_reg, cmp_size};
			}
			if (analysis::types::to_data_size(right_prim_type) != cmp_size) {
				// extend right
				program.push_back(assembly::assembly_instruction(
					signed_comparison ? machine::operation::MOVSX : machine::operation::MOVZX,
					assembly::assembly_result({right_reg, cmp_size}),
					assembly::assembly_operand({right_reg, analysis::types::to_data_size(right_prim_type)})
				));
				right_reg_t = {right_reg, cmp_size};
			}
			// compare
			program.push_back(assembly::assembly_instruction(
				machine::operation::CMP,
				assembly::assembly_operand(left_reg_t),
				assembly::assembly_operand(right_reg_t)
			));
			// set target_reg based on comparison
			machine::operation set_op;
			switch (binary.op) {
				case analysis::expressions::binary_expression::operator_t::EQ:
					set_op = machine::operation::SETZ;
					break;
				case analysis::expressions::binary_expression::operator_t::NEQ:
					set_op = machine::operation::SETNZ;
					break;
				case analysis::expressions::binary_expression::operator_t::LT:
					set_op = signed_comparison ? machine::operation::SETL : machine::operation::SETB;
					break;
				case analysis::expressions::binary_expression::operator_t::LTE:
					set_op = signed_comparison ? machine::operation::SETLE : machine::operation::SETBE;
					break;
				case analysis::expressions::binary_expression::operator_t::GT:
					set_op = signed_comparison ? machine::operation::SETG : machine::operation::SETA;
					break;
				case analysis::expressions::binary_expression::operator_t::GTE:
					set_op = signed_comparison ? machine::operation::SETGE : machine::operation::SETAE;
					break;
				default:
					throw std::runtime_error("Unknown comparison operator");
			}
			program.push_back(assembly::assembly_instruction(
				set_op,
				assembly::assembly_result(target_reg)
			));

			// restore right_reg if needed
			if (right_is_used) {
				program.push_back(assembly::assembly_instruction(
					machine::operation::POP,
					assembly::assembly_operand({right_reg, machine::register_access::dword})
				));
			}
			return;
		}
		if (binary.op != analysis::expressions::binary_expression::operator_t::LAND &&
			binary.op != analysis::expressions::binary_expression::operator_t::LOR) {
			throw std::runtime_error("Unexpected operator in boolean binary expression");
		}
		// logical and / or
		/*
		 * Result (and, or is similar, jnz instead of jz):
		 * - find reg tmp
		 * (push reg tmp)
		 * leftexpr -> target
		 * test target target
		 * lea (eip + size of jz + size of rightexpr) -> tmp
		 * jz tmp
		 * rightexpr -> target
		 * (pop reg tmp)
		 */
		// find a free register (order to check: ecx, eax, edx, ebx)
		machine::register_id tmp_reg = find_free_register(
			used_regs,
			{machine::register_id::ecx, machine::register_id::eax, machine::register_id::edx, machine::register_id::ebx},
			{target_reg.id}
		);
		modified_regs.set(tmp_reg, true);
		used_regs.set(target_reg.id, false);
		bool tmp_is_used = used_regs.get(tmp_reg);
		if (tmp_is_used) {
			// need to save tmp_reg
			program.push_back(assembly::assembly_instruction(
				machine::operation::PUSH,
				assembly::assembly_operand({tmp_reg, machine::register_access::dword})
			));
		}
		used_regs.set(tmp_reg, false);
		machine::register_t bool_reg{target_reg.id, machine::register_access::low_byte};
		compile_primitive_expression(
			*binary.left, context, program, current_scope,
			bool_reg, used_regs, modified_regs, statement_index
		);
		// test target_reg
		program.push_back(assembly::assembly_instruction(
			machine::operation::TEST,
			assembly::assembly_operand(bool_reg),
			assembly::assembly_operand(bool_reg)
		));
		// jump if zero (and) / not zero (or)
		assembly::assembly_program_t temp_program;
		temp_program.push_back(assembly::assembly_instruction(
			binary.op == analysis::expressions::binary_expression::operator_t::LAND
			? machine::operation::JZ
			: machine::operation::JNZ,
			assembly::assembly_operand({tmp_reg, machine::register_access::dword})
		));
		compile_primitive_expression(
			*binary.right, context, temp_program, current_scope,
			bool_reg, used_regs, modified_regs, statement_index
		);
		uint32_t size = assembly::program_size(temp_program);
		// dummy instruction for size calculation
		auto dummy = assembly::assembly_instruction(
			machine::operation::LEA,
			assembly::assembly_result({tmp_reg, machine::register_access::dword}),
			assembly::assembly_memory(machine::register_id::eip, 0)
		);
		size += dummy.instruction_size();
		// lea (eip + size) -> tmp_reg
		program.push_back(assembly::assembly_instruction(
			machine::operation::LEA,
			assembly::assembly_result({tmp_reg, machine::register_access::dword}),
			assembly::assembly_memory(
				machine::register_id::eip,
				static_cast<int32_t>(size)
			)
		));
		// insert the temp program now
		program.insert(program.end(), temp_program.begin(), temp_program.end());
		// zero-extend target_reg to target size
		if (target_reg.access != machine::register_access::low_byte)
			program.push_back(assembly::assembly_instruction(
				machine::operation::MOVZX,
				assembly::assembly_result(target_reg),
				assembly::assembly_operand(bool_reg)
			));
		// restore tmp_reg if needed
		if (tmp_is_used) {
			program.push_back(assembly::assembly_instruction(
				machine::operation::POP,
				assembly::assembly_operand({tmp_reg, machine::register_access::dword})
			));
		}
		return;
	}

	void compile_pointer_expression(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		regmask& modified_regs,
		const analysis::types::type_node& dest_type,
		uint32_t statement_index
	) {
		switch (expr.kind) {
			case analysis::expressions::expression_node::kind_t::LITERAL: {
				const auto& lit = std::get<analysis::expressions::literal_expression>(expr.value);
				if (lit.kind != analysis::expressions::literal_expression::kind_t::UINT) {
					throw std::runtime_error("Only integer literals can be compiled to pointer types");
				}
				uint32_t addr = std::get<uint32_t>(lit.value);
				program.push_back(assembly::assembly_instruction(
					machine::operation::MOV,
					assembly::assembly_result({target_reg.id, machine::register_access::dword}),
					assembly::assembly_operand(addr)
				));
				return;
			}
			case analysis::expressions::expression_node::kind_t::IDENTIFIER: {
				const auto& ident = std::get<analysis::expressions::identifier_expression>(expr.value);
				if (!context.variable_storage->is_variable_declared(ident.name)) {
					throw std::runtime_error("Variable not found: " + ident.name);
				}
				const auto declaring_scope = context.variable_storage->get_declaring_scope(ident.name);
				const auto var_info = declaring_scope->get_variable(ident.name, false);
				switch (declaring_scope->storage_type) {
					case analysis::variables::storage::storage_type_t::Global:
						throw std::runtime_error("Loading global variables is not supported yet");
					case analysis::variables::storage::storage_type_t::Function: {
						// Variable is a parameter passed to the function
						auto func_sig = context.current_function_signature;
						if (func_sig == nullptr) {
							throw std::runtime_error("Current function signature is null");
						}
						// find the parameter index
						uint32_t idx = func_sig->name_index_map.at(ident.name);
						auto param = func_sig->parameters[idx];
						uint32_t offset = param.offset;
						// move the parameter to the target register
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result({target_reg.id, machine::register_access::dword}),
							assembly::assembly_operand({
								machine::data_size_t::DWORD,
								assembly::assembly_memory(
									machine::register_t{machine::register_id::ebp},
									static_cast<int32_t>(offset)
								)
							})
						));
						return;
					}
					case analysis::variables::storage::storage_type_t::Block: {
						// Variable is a local variable
						auto var = current_scope.get_variable(ident.name, true);
						// offset is negative from ebp
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result({target_reg.id, machine::register_access::dword}),
							assembly::assembly_operand({
								machine::data_size_t::DWORD,
								assembly::assembly_memory(
									machine::register_t{machine::register_id::ebp},
									static_cast<int32_t>(-static_cast<int32_t>(var.offset))
								)
							})
						));
						return;
					}
				}
				throw std::runtime_error("Unknown variable storage type");
			}
			case analysis::expressions::expression_node::kind_t::UNARY: {
				const auto& unary = std::get<analysis::expressions::unary_expression>(expr.value);
				switch (unary.op) {
					case analysis::expressions::unary_expression::operator_t::ADDRESS_OF: {
						used_regs.set(target_reg.id, false);
						assembly::assembly_program_t temp_program;
						auto ref = compile_reference(
							*unary.operand, context, temp_program,
							current_scope, used_regs, modified_regs, statement_index
						);
						regmask ref_regs = get_containing_regs(ref);
						regmask overlap = ref_regs & used_regs;
						// save overlapping registers
						std::vector<machine::register_t> saved_regs;
						for (const auto r : regmask::USABLE_REGISTERS) {
							if (overlap.get(r)) {
								program.emplace_back(assembly::assembly_instruction(
									machine::operation::PUSH,
									assembly::assembly_operand{r}
								));
								saved_regs.emplace_back(r);
							}
						}
						// insert the temp program now
						program.insert(program.end(), temp_program.begin(), temp_program.end());
						// load address into target_reg
						program.emplace_back(assembly::assembly_instruction(
							machine::operation::LEA,
							assembly::assembly_result{target_reg},
							ref
						));
						// now restore the saved registers
						for (auto it = saved_regs.rbegin(); it != saved_regs.rend(); ++it) {
							program.emplace_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result{*it}
							));
						}
						return;
					}
					case analysis::expressions::unary_expression::operator_t::DEREFERENCE: {
						// dereference the pointer
						auto operand_type = unary.operand->get_type(
							*context.variable_storage,
							*context.global_context->function_storage,
							*context.global_context->type_system
						);
						auto resolved_operand_type = context.global_context->type_system->resolved_type(operand_type);
						if (resolved_operand_type.kind != analysis::types::type_node::kind_t::POINTER) {
							throw std::runtime_error("Operand of dereference must be a pointer type");
						}
						auto ptr_type = std::get<analysis::types::pointer_type>(resolved_operand_type.value);
						auto pointee_type = context.global_context->type_system->resolved_type(*ptr_type.pointee_type);
						if (!context.global_context->type_system->is_equivalent(resolved_operand_type, dest_type, {
							true, true, false
						})) {
							throw std::runtime_error("Pointer type does not match target pointer type");
						}
						compile_primitive_expression(
							*unary.operand, context, program, current_scope,
							target_reg, used_regs, modified_regs, statement_index
						);
						// now target_reg contains the address of the pointer, so we need to load the value at that address
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result({target_reg.id, machine::register_access::dword}),
							assembly::assembly_operand({
								machine::data_size_t::DWORD,
								assembly::assembly_memory(target_reg.id)
							})
						));
						return;
					}
					default:
						break;
				}
				break;
			}
			case analysis::expressions::expression_node::kind_t::BINARY: {
			}
		}
	}

	void compile_primitive_expression(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		bool store_value
	) {
		auto dest_type = context.global_context->type_system->resolved_type(
			expr.get_type(
				*context.variable_storage,
				*context.global_context->function_storage,
				*context.global_context->type_system
			)
		);
		if (expr.kind == analysis::expressions::expression_node::kind_t::MEMBER) {
			const auto& member_access = std::get<analysis::expressions::member_expression>(expr.value);
			// get the type of the object
			auto base_object_type = member_access.object->get_type(
				*context.variable_storage,
				*context.global_context->function_storage,
				*context.global_context->type_system
			);
			auto resolved_base_object_type = context.global_context->type_system->resolved_type(base_object_type);
			analysis::types::type_node object_type;
			if (member_access.pointer) {
				if (resolved_base_object_type.kind != analysis::types::type_node::kind_t::POINTER) {
					throw std::runtime_error("Base object of pointer member access must be a pointer");
				}
				auto ptr_type = std::get<analysis::types::pointer_type>(resolved_base_object_type.value);
				object_type = context.global_context->type_system->resolved_type(*ptr_type.pointee_type);
			}
			else
				object_type = resolved_base_object_type;
			assembly::assembly_program_t temp_program;
			used_regs.set(target_reg.id, false);
			auto ref = compile_reference(
				*member_access.object, context, temp_program,
				current_scope, used_regs, modified_regs, statement_index
			);
			regmask ref_regs = get_containing_regs(ref);
			regmask overlap = ref_regs & used_regs;
			// save overlapping registers
			std::vector<machine::register_t> saved_regs;
			for (const auto r : regmask::USABLE_REGISTERS) {
				if (overlap.get(r)) {
					program.emplace_back(assembly::assembly_instruction(
						machine::operation::PUSH,
						assembly::assembly_operand{r}
					));
					saved_regs.emplace_back(r);
				}
			}
			// insert the temp program now
			program.insert(program.end(), temp_program.begin(), temp_program.end());
			// pointers and function pointers are always 4 bytes
			machine::data_size_t mem_size = dest_type.kind == analysis::types::type_node::kind_t::PRIMITIVE
				? analysis::types::to_data_size(std::get<analysis::types::primitive_type>(dest_type.value))
				: machine::data_size_t::DWORD;
			// copy the value to target_reg
			if (member_access.pointer) {
				program.push_back(assembly::assembly_instruction(
					machine::operation::MOV,
					assembly::assembly_result(target_reg.id),
					assembly::assembly_operand({
						machine::data_size_t::DWORD,
						ref
					})
				));
				// now target_reg contains the address of the object, so we need to load the member from that address
				if (object_type.kind == analysis::types::type_node::kind_t::STRUCT) {
					auto struct_type = std::get<analysis::types::struct_type>(object_type.value);
					auto member_info = context.global_context->type_system->get_struct_member_info(struct_type,
						member_access.member);
					program.push_back(assembly::assembly_instruction(
						machine::operation::MOV,
						assembly::assembly_result(target_reg),
						assembly::assembly_operand({
							mem_size,
							assembly::assembly_memory(
								target_reg.id,
								static_cast<int32_t>(member_info.offset)
							)
						})
					));
				}
				else if (object_type.kind == analysis::types::type_node::kind_t::UNION) {
					// just load the base object
					program.push_back(assembly::assembly_instruction(
						machine::operation::MOV,
						assembly::assembly_result(target_reg),
						assembly::assembly_operand({
							mem_size,
							assembly::assembly_memory(target_reg.id)
						})
					));
				}
				else {
					throw std::runtime_error("Base object of member access must be a struct or union");
				}
			}
			else {
				if (object_type.kind == analysis::types::type_node::kind_t::STRUCT) {
					auto struct_type = std::get<analysis::types::struct_type>(object_type.value);
					auto member_info = context.global_context->type_system->get_struct_member_info(struct_type,
						member_access.member);
					// load the member into target_reg
					switch (ref.memory_type) {
						case assembly::assembly_memory::type::DIRECT: {
							// direct memory access, just add offset to address
							auto val = std::get<assembly::extended_assembly_literal>(ref.value);
							program.push_back(assembly::assembly_instruction(
								machine::operation::MOV,
								assembly::assembly_result(target_reg),
								assembly::assembly_operand({
									mem_size,
									assembly::assembly_memory(
										assembly::extended_assembly_literal(
											assembly::extended_assembly_literal::type_t::ADD,
											std::make_shared<assembly::extended_assembly_literal>(val),
											std::make_shared<assembly::extended_assembly_literal>(
												assembly::assembly_literal(static_cast<int32_t>(member_info.offset))
											)
										)
									)
								})
							));
							break;
						}
						case assembly::assembly_memory::type::REGISTER: {
							// register, create displacement
							auto reg = std::get<machine::register_t>(ref.value);
							program.push_back(assembly::assembly_instruction(
								machine::operation::MOV,
								assembly::assembly_result(target_reg),
								assembly::assembly_operand({
									mem_size,
									assembly::assembly_memory(
										reg,
										static_cast<int32_t>(member_info.offset)
									)
								})
							));
							break;
						}
						case assembly::assembly_memory::type::DISPLACEMENT: {
							// displacement, add to existing displacement
							auto disp = std::get<assembly::assembly_memory::displacement>(ref.value);
							program.push_back(assembly::assembly_instruction(
								machine::operation::MOV,
								assembly::assembly_result(target_reg),
								assembly::assembly_operand({
									mem_size,
									assembly::assembly_memory(
										disp.reg,
										assembly::extended_assembly_literal(
											assembly::extended_assembly_literal::type_t::ADD,
											std::make_shared<assembly::extended_assembly_literal>(disp.disp),
											std::make_shared<assembly::extended_assembly_literal>(
												assembly::assembly_literal(static_cast<int32_t>(member_info.offset))
											)
										)
									)
								})
							));
							break;
						}
						case assembly::assembly_memory::type::SCALED_INDEX: {
							// scaled index, add to existing displacement
							auto si = std::get<assembly::assembly_memory::scaled_index>(ref.value);
							program.push_back(assembly::assembly_instruction(
								machine::operation::MOV,
								assembly::assembly_result(target_reg),
								assembly::assembly_operand({
									mem_size,
									assembly::assembly_memory(
										si.base,
										si.index,
										si.scale,
										assembly::assembly_literal(static_cast<int32_t>(member_info.offset))
									)
								})
							));
							break;
						}
						case assembly::assembly_memory::type::SCALED_INDEX_DISPLACEMENT: {
							// scaled index with displacement, add to existing displacement
							auto sid = std::get<assembly::assembly_memory::scaled_index_displacement>(ref.value);
							program.push_back(assembly::assembly_instruction(
								machine::operation::MOV,
								assembly::assembly_result(target_reg),
								assembly::assembly_operand({
									mem_size,
									assembly::assembly_memory(
										sid.base,
										sid.index,
										sid.scale,
										assembly::extended_assembly_literal(
											assembly::extended_assembly_literal::type_t::ADD,
											std::make_shared<assembly::extended_assembly_literal>(sid.disp),
											std::make_shared<assembly::extended_assembly_literal>(
												assembly::assembly_literal(static_cast<int32_t>(member_info.offset))
											)
										)
									)
								})
							));
							break;
						}
					}
				}
				else if (object_type.kind == analysis::types::type_node::kind_t::UNION) {
					// just load the base object
					program.push_back(assembly::assembly_instruction(
						machine::operation::MOV,
						assembly::assembly_result(target_reg),
						assembly::assembly_operand({
							mem_size,
							ref
						})
					));
				}
				else {
					throw std::runtime_error("Base object of member access must be a struct or union");
				}
			}
			// now restore the saved registers
			for (auto it = saved_regs.rbegin(); it != saved_regs.rend(); ++it) {
				program.emplace_back(assembly::assembly_instruction(
					machine::operation::POP,
					assembly::assembly_result{*it}
				));
			}
			return;
		}
		if (expr.kind == analysis::expressions::expression_node::kind_t::CALL) {
			const auto& call = std::get<analysis::expressions::call_expression>(expr.value);
			enum class call_type_t {
				Direct,
				Variable,
				Complex
			};
			call_type_t call_type;
			analysis::types::function_type func_type;
			if (call.callee->kind == analysis::expressions::expression_node::kind_t::IDENTIFIER &&
				!context.variable_storage->is_variable_declared(
					std::get<analysis::expressions::identifier_expression>(call.callee->value).name)) {
				// global function
				call_type = call_type_t::Direct;
				const auto& func_info =
					context.global_context->function_storage->get_function(
						std::get<analysis::expressions::identifier_expression>(call.callee->value).name
					);
				func_type.parameter_types.reserve(func_info.parameter_types.size());
				for (const auto& param : func_info.parameter_types) {
					func_type.parameter_types.emplace_back(std::make_shared<analysis::types::type_node>(param));
				}
				func_type.return_type = std::make_shared<analysis::types::type_node>(func_info.return_type);
			}
			else {
				auto callee_type = call.callee->get_type(
					*context.variable_storage,
					*context.global_context->function_storage,
					*context.global_context->type_system
				);
				auto resolved_callee_type = context.global_context->type_system->resolved_type(callee_type);
				if (resolved_callee_type.kind != analysis::types::type_node::kind_t::FUNCTION) {
					throw std::runtime_error("Callee expression does not evaluate to a function");
				}
				func_type = std::get<analysis::types::function_type>(resolved_callee_type.value);
				if (call.callee->kind == analysis::expressions::expression_node::kind_t::IDENTIFIER) {
					call_type = call_type_t::Variable;
				}
				else {
					call_type = call_type_t::Complex;
					// complex expression, need to evaluate to get address
					used_regs.set(target_reg.id, false);
					compile_primitive_expression(
						*call.callee, context, program, current_scope,
						target_reg, used_regs, modified_regs, statement_index
					);
					used_regs.set(target_reg.id, true);
				}
			}
			uint32_t param_stack_size = 0;
			for (const auto& param_type : func_type.parameter_types) {
				param_stack_size += context.global_context->type_system->get_type_size(*param_type);
			}
			uint32_t ret_size = context.global_context->type_system->get_type_size(*func_type.return_type);
			if (param_stack_size < ret_size) {
				program.emplace_back(assembly::assembly_instruction(
					machine::operation::SUB,
					assembly::assembly_result({machine::register_id::esp, machine::register_access::dword}),
					assembly::assembly_operand(ret_size - param_stack_size)
				));
			}
			machine::register_id param_reg = find_free_register(
				used_regs,
				{machine::register_id::edx, machine::register_id::ebx, machine::register_id::ecx, machine::register_id::eax},
				{target_reg.id}
			);
			modified_regs.set(param_reg, true);
			const bool param_reg_used = used_regs.get(param_reg);
			if (param_reg_used) {
				// need to save param_reg
				program.push_back(assembly::assembly_instruction(
					machine::operation::PUSH,
					assembly::assembly_operand({param_reg, machine::register_access::dword})
				));
			}
			used_regs.set(param_reg, false);
			// push parameters in reverse order
			for (int i = static_cast<int>(call.arguments.size()) - 1; i >= 0; --i) {
				auto arg = call.arguments[i];
				auto param_type = func_type.parameter_types[i];
				auto resolved_param_type = context.global_context->type_system->resolved_type(*param_type);
				auto arg_type = arg->get_type(
					*context.variable_storage,
					*context.global_context->function_storage,
					*context.global_context->type_system
				);
				auto resolved_arg_type = context.global_context->type_system->resolved_type(arg_type);
				if (resolved_param_type.kind != analysis::types::type_node::kind_t::PRIMITIVE &&
					resolved_param_type.kind != analysis::types::type_node::kind_t::POINTER &&
					resolved_param_type.kind != analysis::types::type_node::kind_t::FUNCTION) {
					throw std::runtime_error("Currently only supports primitives, pointers and functions as parameters");
				}
				if (resolved_param_type.kind == analysis::types::type_node::kind_t::PRIMITIVE &&
					resolved_arg_type.kind == analysis::types::type_node::kind_t::PRIMITIVE) {
					// both are primitive, check if they are compatible
					auto param_prim_type = std::get<analysis::types::primitive_type>(resolved_param_type.value);
					auto arg_prim_type = std::get<analysis::types::primitive_type>(resolved_arg_type.value);
					if (!analysis::types::can_implicitly_convert(arg_prim_type, param_prim_type)) {
						throw std::runtime_error("Argument type does not match function signature");
					}
				}
				else if (!context.global_context->type_system->is_equivalent(resolved_param_type, resolved_arg_type)) {
					throw std::runtime_error("Argument type does not match function signature");
				}
				machine::data_size_t param_size = resolved_param_type.kind == analysis::types::type_node::kind_t::PRIMITIVE
					? analysis::types::to_data_size(std::get<analysis::types::primitive_type>(resolved_param_type.value))
					: machine::data_size_t::DWORD;
				compile_primitive_expression(
					*arg, context, program, current_scope,
					{param_reg, param_size}, used_regs, modified_regs, statement_index
				);
				// push param_reg onto stack
				program.push_back(assembly::assembly_instruction(
					machine::operation::PUSH,
					assembly::assembly_operand({param_reg, param_size})
				));
			}
			// now call the function
			if (call_type == call_type_t::Direct) {
				const auto& function_label = generate_function_label(
					std::get<analysis::expressions::identifier_expression>(call.callee->value).name
				);
				program.push_back(assembly::assembly_instruction(
					machine::operation::CALL,
					assembly::assembly_operand(function_label)
				));
			}
			else if (call_type == call_type_t::Variable) {
				const auto& ident = std::get<analysis::expressions::identifier_expression>(call.callee->value);
				if (!context.variable_storage->is_variable_declared(ident.name)) {
					throw std::runtime_error("Variable not found: " + ident.name);
				}
				const auto declaring_scope = context.variable_storage->get_declaring_scope(ident.name);
				const auto var_info = declaring_scope->get_variable(ident.name, false);
				switch (declaring_scope->storage_type) {
					case analysis::variables::storage::storage_type_t::Global:
						throw std::runtime_error("Loading global variables is not supported yet");
					case analysis::variables::storage::storage_type_t::Function: {
						// Variable is a parameter passed to the function
						auto func_sig = context.current_function_signature;
						if (func_sig == nullptr) {
							throw std::runtime_error("Current function signature is null");
						}
						// find the parameter index
						uint32_t idx = func_sig->name_index_map.at(ident.name);
						auto param = func_sig->parameters[idx];
						uint32_t offset = param.offset;
						// move the parameter to the target register
						program.push_back(assembly::assembly_instruction(
							machine::operation::CALL,
							assembly::assembly_operand({
								machine::data_size_t::DWORD,
								assembly::assembly_memory(
									machine::register_t{machine::register_id::ebp},
									static_cast<int32_t>(offset)
								)
							})
						));
						break;
					}
					case analysis::variables::storage::storage_type_t::Block: {
						// Variable is a local variable
						auto var = current_scope.get_variable(ident.name, true);
						// offset is negative from ebp
						program.push_back(assembly::assembly_instruction(
							machine::operation::CALL,
							assembly::assembly_operand({
								machine::data_size_t::DWORD,
								assembly::assembly_memory(
									machine::register_t{machine::register_id::ebp},
									-static_cast<int32_t>(var.offset)
								)
							})
						));
						break;
					}
				}
			}
			else {
				// complex expression, address is already in target_reg
				program.push_back(assembly::assembly_instruction(
					machine::operation::CALL,
					assembly::assembly_operand({target_reg.id, machine::register_access::dword})
				));
			}
			// the return value is stored on the stack starting at the position of the first parameter (the one that was pushed last)
			// that just means it's at [esp]
			// move it to target_reg
			// if the return size is 0 (void), do nothing
			if (ret_size > 0 && store_value) {
				machine::data_size_t ret_data_size =
					ret_size == 1
					? machine::data_size_t::BYTE
					: ret_size == 2
					? machine::data_size_t::WORD
					: machine::data_size_t::DWORD;
				program.push_back(assembly::assembly_instruction(
					machine::operation::MOV,
					assembly::assembly_result(target_reg),
					assembly::assembly_operand({
						ret_data_size,
						assembly::assembly_memory(
							machine::register_id::esp
						)
					})
				));
			}
			// clean up the stack
			if (param_stack_size > 0 || ret_size > param_stack_size) {
				program.push_back(assembly::assembly_instruction(
					machine::operation::ADD,
					assembly::assembly_result({machine::register_id::esp, machine::register_access::dword}),
					assembly::assembly_operand(std::max(param_stack_size, ret_size))
				));
			}
			// restore param_reg if needed
			if (param_reg_used) {
				program.push_back(assembly::assembly_instruction(
					machine::operation::POP,
					assembly::assembly_operand({param_reg, machine::register_access::dword})
				));
			}
			return;
		}
		if (dest_type.kind == analysis::types::type_node::kind_t::POINTER) {
			auto pointer_type = std::get<analysis::types::pointer_type>(dest_type.value);
			auto pointee_type = context.global_context->type_system->resolved_type(*pointer_type.pointee_type);
			compile_pointer_expression(
				expr, context, program, current_scope,
				target_reg, used_regs, modified_regs, pointee_type, statement_index
			);
			return;
		}
		if (dest_type.kind != analysis::types::type_node::kind_t::PRIMITIVE) {
			throw std::runtime_error("Only primitive and pointer types can be compiled to a register");
		}
		const auto& prim_type = std::get<analysis::types::primitive_type>(dest_type.value);
		switch (expr.kind) {
			case analysis::expressions::expression_node::kind_t::LITERAL: {
				const auto& lit = std::get<analysis::expressions::literal_expression>(expr.value);
				switch (lit.kind) {
					case analysis::expressions::literal_expression::kind_t::BOOL:
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result({target_reg.id, machine::register_access::low_byte}),
							assembly::assembly_operand(std::get<bool>(lit.value) ? 1 : 0)
						));
						return;
					case analysis::expressions::literal_expression::kind_t::CHAR:
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result({target_reg.id, machine::register_access::low_byte}),
							assembly::assembly_operand(static_cast<int8_t>(std::get<char>(lit.value)))
						));
						return;
					case analysis::expressions::literal_expression::kind_t::UINT:
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result({target_reg.id, machine::register_access::dword}),
							assembly::assembly_operand(std::get<uint32_t>(lit.value))
						));
						return;
					case analysis::expressions::literal_expression::kind_t::INT:
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result({target_reg.id, machine::register_access::dword}),
							assembly::assembly_operand(std::get<int32_t>(lit.value))
						));
						return;
					default:
						break;
				}
				throw std::runtime_error("Unknown literal type");
			}
			case analysis::expressions::expression_node::kind_t::IDENTIFIER: {
				const auto& ident = std::get<analysis::expressions::identifier_expression>(expr.value);
				if (!context.variable_storage->is_variable_declared(ident.name)) {
					throw std::runtime_error("Variable not found: " + ident.name);
				}
				const auto declaring_scope = context.variable_storage->get_declaring_scope(ident.name);
				const auto var_info = declaring_scope->get_variable(ident.name, false);
				switch (declaring_scope->storage_type) {
					case analysis::variables::storage::storage_type_t::Global:
						throw std::runtime_error("Loading global variables is not supported yet");
					case analysis::variables::storage::storage_type_t::Function: {
						// Variable is a parameter passed to the function
						auto func_sig = context.current_function_signature;
						if (func_sig == nullptr) {
							throw std::runtime_error("Current function signature is null");
						}
						// find the parameter index
						uint32_t idx = func_sig->name_index_map.at(ident.name);
						auto param = func_sig->parameters[idx];
						uint32_t offset = param.offset;
						// move the parameter to the target register
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result({target_reg.id, machine::register_access::dword}),
							assembly::assembly_operand({
								analysis::types::to_data_size(prim_type),
								assembly::assembly_memory(
									machine::register_t{machine::register_id::ebp},
									static_cast<int32_t>(offset)
								)
							})
						));
						return;
					}
					case analysis::variables::storage::storage_type_t::Block: {
						// Variable is a local variable
						auto var = current_scope.get_variable(ident.name, true);
						// offset is negative from ebp
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result({target_reg.id, machine::register_access::dword}),
							assembly::assembly_operand({
								analysis::types::to_data_size(prim_type),
								assembly::assembly_memory(
									machine::register_t{machine::register_id::ebp},
									-static_cast<int32_t>(var.offset)
								)
							})
						));
						return;
					}
				}
				throw std::runtime_error("Unknown variable storage type");
			}
			case analysis::expressions::expression_node::kind_t::UNARY: {
				const auto& unary = std::get<analysis::expressions::unary_expression>(expr.value);
				const auto& operand = *unary.operand;
				auto operand_type = context.global_context->type_system->resolved_type(
					operand.get_type(
						*context.variable_storage,
						*context.global_context->function_storage,
						*context.global_context->type_system
					)
				);
				if (operand_type.kind != analysis::types::type_node::kind_t::PRIMITIVE &&
					operand_type.kind != analysis::types::type_node::kind_t::POINTER) {
					throw std::runtime_error("Unary operator can only be applied to primitive or pointer types");
				}
				switch (unary.op) {
					case analysis::expressions::unary_expression::operator_t::ADDRESS_OF:
						throw std::runtime_error("This should be a pointer type");
					case analysis::expressions::unary_expression::operator_t::DEREFERENCE: {
						auto addr_type = unary.operand->get_type(
							*context.variable_storage,
							*context.global_context->function_storage,
							*context.global_context->type_system
						);
						auto resolved_addr_type = context.global_context->type_system->resolved_type(addr_type);
						if (resolved_addr_type.kind != analysis::types::type_node::kind_t::POINTER) {
							throw std::runtime_error("Dereference operator requires a pointer type");
						}
						auto ptr_type = std::get<analysis::types::pointer_type>(resolved_addr_type.value);
						auto pointee_type = context.global_context->type_system->resolved_type(*ptr_type.pointee_type);
						if (pointee_type.kind != analysis::types::type_node::kind_t::PRIMITIVE) {
							throw std::runtime_error("The dereferenced type should be a primitive type");
						}
						auto pointee_prim_type = std::get<analysis::types::primitive_type>(pointee_type.value);
						compile_primitive_expression(
							*unary.operand, context, program, current_scope,
							target_reg, used_regs, modified_regs, statement_index
						);
						// now target_reg contains the address, load the value from that address
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result(target_reg),
							assembly::assembly_operand({
								analysis::types::to_data_size(pointee_prim_type),
								assembly::assembly_memory(target_reg.id)
							})
						));
						return;
					}
					case analysis::expressions::unary_expression::operator_t::MINUS: {
						compile_primitive_expression(
							*unary.operand, context, program, current_scope,
							target_reg, used_regs, modified_regs, statement_index
						);
						// negate the value in target_reg
						program.push_back(assembly::assembly_instruction(
							machine::operation::NEG,
							assembly::assembly_result(target_reg)
						));
						return;
					}
					case analysis::expressions::unary_expression::operator_t::NOT: {
						compile_primitive_expression(
							*unary.operand, context, program, current_scope,
							target_reg, used_regs, modified_regs, statement_index
						);
						// perform bitwise NOT on the value in target_reg
						program.push_back(assembly::assembly_instruction(
							machine::operation::NOT,
							assembly::assembly_result(target_reg)
						));
						return;
					}
					case analysis::expressions::unary_expression::operator_t::LNOT: {
						compile_primitive_expression(
							*unary.operand, context, program, current_scope,
							target_reg.id, used_regs, modified_regs, statement_index
						);
						// compare the value in target_reg with 0 and set to 1 if equal, else 0
						program.push_back(assembly::assembly_instruction(
							machine::operation::CMP,
							assembly::assembly_operand(target_reg.id),
							assembly::assembly_operand(0)
						));
						program.push_back(assembly::assembly_instruction(
							machine::operation::SETZ,
							assembly::assembly_result(target_reg)
						));
						return;
					}
					case analysis::expressions::unary_expression::operator_t::PLUS: {
						compile_primitive_expression(
							*unary.operand, context, program, current_scope,
							target_reg, used_regs, modified_regs, statement_index
						);
						return;
					}
					case analysis::expressions::unary_expression::operator_t::SIZEOF:
						throw std::runtime_error("Sizeof operator not implemented yet");
					case analysis::expressions::unary_expression::operator_t::PRE_DEC:
					case analysis::expressions::unary_expression::operator_t::PRE_INC: {
						// getting the reference to the expression already modifies it for us
						assembly::assembly_program_t temp_program;
						auto ref = compile_reference(
							unary, context, temp_program,
							current_scope, used_regs, modified_regs, statement_index
						);
						regmask ref_regs = get_containing_regs(ref);
						regmask overlap = ref_regs & used_regs;
						std::vector<machine::register_t> saved_regs;
						// save overlapping registers
						for (const auto r : regmask::USABLE_REGISTERS) {
							if (overlap.get(r) && r != target_reg.id) {
								program.emplace_back(assembly::assembly_instruction(
									machine::operation::PUSH,
									assembly::assembly_operand{r}
								));
								saved_regs.emplace_back(r);
							}
						}
						// insert the temp program now
						program.insert(program.end(), temp_program.begin(), temp_program.end());
						// load the value from the reference into target_reg
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result(target_reg),
							assembly::assembly_operand({
								analysis::types::to_data_size(prim_type),
								ref
							})
						));
						// restore saved registers
						for (auto it = saved_regs.rbegin(); it != saved_regs.rend(); ++it) {
							program.emplace_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result{*it}
							));
						}
						return;
					}
					case analysis::expressions::unary_expression::operator_t::POST_DEC:
					case analysis::expressions::unary_expression::operator_t::POST_INC: {
						auto operand_prim_type = std::get<analysis::types::primitive_type>(operand_type.value);
						used_regs.set(target_reg.id, true);
						// get reference to the operand
						assembly::assembly_program_t temp_program;
						auto ref = compile_reference(
							*unary.operand, context, temp_program,
							current_scope, used_regs, modified_regs, statement_index
						);
						regmask ref_regs = get_containing_regs(ref);
						bool value_stored = ref_regs.get(target_reg.id);
						regmask overlap = ref_regs & used_regs;
						std::vector<machine::register_t> saved_regs;
						for (const auto r : regmask::USABLE_REGISTERS) {
							if (overlap.get(r) && r != target_reg.id) {
								program.emplace_back(assembly::assembly_instruction(
									machine::operation::PUSH,
									assembly::assembly_operand{r}
								));
								saved_regs.emplace_back(r);
							}
						}
						// insert the temp program now
						program.insert(program.end(), temp_program.begin(), temp_program.end());
						if (value_stored) {
							// push the value from the reference onto the stack
							program.push_back(assembly::assembly_instruction(
								machine::operation::PUSH,
								assembly::assembly_operand({
									analysis::types::to_data_size(prim_type),
									ref
								})
							));
						}
						else {
							// load the value from the reference into target_reg
							program.push_back(assembly::assembly_instruction(
								machine::operation::MOV,
								assembly::assembly_result(target_reg),
								assembly::assembly_operand({
									analysis::types::to_data_size(prim_type),
									ref
								})
							));
						}
						// increment/decrement the value in the reference
						program.push_back(assembly::assembly_instruction(
							unary.op == analysis::expressions::unary_expression::operator_t::POST_INC
							? machine::operation::INC
							: machine::operation::DEC,
							assembly::assembly_result({
								analysis::types::to_data_size(operand_prim_type),
								ref
							})
						));
						// pop value into target_reg if not already there
						if (value_stored) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result(target_reg)
							));
						}
						// restore saved registers
						for (auto it = saved_regs.rbegin(); it != saved_regs.rend(); ++it) {
							program.emplace_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result{*it}
							));
						}
						return;
					}
				}
			}
			case analysis::expressions::expression_node::kind_t::BINARY: {
				const auto& binary = std::get<analysis::expressions::binary_expression>(expr.value);
				const auto& left = *binary.left;
				const auto& right = *binary.right;
				auto left_type = context.global_context->type_system->resolved_type(
					left.get_type(
						*context.variable_storage,
						*context.global_context->function_storage,
						*context.global_context->type_system
					)
				);
				auto right_type = context.global_context->type_system->resolved_type(
					right.get_type(
						*context.variable_storage,
						*context.global_context->function_storage,
						*context.global_context->type_system
					)
				);
				// we can't say for sure that both sides are primitive types (comparisons for example returns bool)
				// here we expect both sides to be primitive types (sub, comparisons also allow two pointers)
				if (left_type.kind == analysis::types::type_node::kind_t::POINTER &&
					right_type.kind == analysis::types::type_node::kind_t::POINTER &&
					(binary.op == analysis::expressions::binary_expression::operator_t::SUB ||
						binary.op == analysis::expressions::binary_expression::operator_t::LT ||
						binary.op == analysis::expressions::binary_expression::operator_t::LTE ||
						binary.op == analysis::expressions::binary_expression::operator_t::GT ||
						binary.op == analysis::expressions::binary_expression::operator_t::GTE ||
						binary.op == analysis::expressions::binary_expression::operator_t::EQ ||
						binary.op == analysis::expressions::binary_expression::operator_t::NEQ)) {
					// this ignores the actual pointer types and just compares the addresses
					// get the value of the left pointer into target_reg
					compile_primitive_expression(
						left, context, program, current_scope,
						target_reg.id, used_regs, modified_regs, statement_index
					);
					// get the value of the right pointer into a different register
					// find a free register or use ebx (order to check: ebx, ecx, eax, edx)
					machine::register_id right_reg_id = find_free_register(
						used_regs,
						{
							machine::register_id::ebx, machine::register_id::ecx, machine::register_id::eax,
							machine::register_id::edx
						},
						{target_reg.id}
					);
					modified_regs.set(right_reg_id, true);
					used_regs.set(target_reg.id, true);
					if (used_regs.get(right_reg_id)) {
						program.push_back(assembly::assembly_instruction(
							machine::operation::PUSH,
							assembly::assembly_operand{right_reg_id}
						));
					}
					compile_primitive_expression(
						right, context, program, current_scope,
						right_reg_id, used_regs, modified_regs, statement_index
					);
					// now perform the operation
					if (binary.op == analysis::expressions::binary_expression::operator_t::SUB) {
						// subtract right from left, result in target_reg
						program.push_back(assembly::assembly_instruction(
							machine::operation::SUB,
							assembly::assembly_result(target_reg),
							assembly::assembly_operand(right_reg_id)
						));
					}
					else {
						// comparisons
						program.push_back(assembly::assembly_instruction(
							machine::operation::CMP,
							assembly::assembly_operand(target_reg.id),
							assembly::assembly_operand(right_reg_id)
						));
						machine::operation set_op;
						// pointer comparisons are always unsigned
						switch (binary.op) {
							case analysis::expressions::binary_expression::operator_t::LT:
								set_op = machine::operation::SETB;
								break;
							case analysis::expressions::binary_expression::operator_t::LTE:
								set_op = machine::operation::SETBE;
								break;
							case analysis::expressions::binary_expression::operator_t::GT:
								set_op = machine::operation::SETA;
								break;
							case analysis::expressions::binary_expression::operator_t::GTE:
								set_op = machine::operation::SETAE;
								break;
							case analysis::expressions::binary_expression::operator_t::EQ:
								set_op = machine::operation::SETZ;
								break;
							case analysis::expressions::binary_expression::operator_t::NEQ:
								set_op = machine::operation::SETNZ;
								break;
							default:
								throw std::runtime_error("Internal error: Unknown comparison operator");
						}
						program.push_back(assembly::assembly_instruction(
							set_op,
							assembly::assembly_result({target_reg.id, machine::register_access::low_byte})
						));
						// zero-extend the result to the full register
						if (target_reg.access != machine::register_access::low_byte) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::MOVZX,
								assembly::assembly_result(target_reg),
								assembly::assembly_operand({target_reg.id, machine::register_access::low_byte})
							));
						}
					}
					// restore right_reg if needed
					if (used_regs.get(right_reg_id)) {
						program.push_back(assembly::assembly_instruction(
							machine::operation::POP,
							assembly::assembly_result{right_reg_id}
						));
					}
					return;
				}
				if (prim_type == analysis::types::primitive_type::BOOL &&
					(binary.op == analysis::expressions::binary_expression::operator_t::EQ ||
						binary.op == analysis::expressions::binary_expression::operator_t::NEQ ||
						binary.op == analysis::expressions::binary_expression::operator_t::LAND ||
						binary.op == analysis::expressions::binary_expression::operator_t::LOR ||
						binary.op == analysis::expressions::binary_expression::operator_t::LT ||
						binary.op == analysis::expressions::binary_expression::operator_t::LTE ||
						binary.op == analysis::expressions::binary_expression::operator_t::GT ||
						binary.op == analysis::expressions::binary_expression::operator_t::GTE)) {
					compile_boolean_binary_expression(
						binary,
						context,
						program,
						current_scope,
						target_reg,
						used_regs,
						modified_regs,
						left_type,
						right_type,
						statement_index
					);
					return;
				}

				if (binary.op == analysis::expressions::binary_expression::operator_t::ARRAY_SUBSCRIPT) {
					if (left_type.kind != analysis::types::type_node::kind_t::POINTER &&
						left_type.kind != analysis::types::type_node::kind_t::ARRAY)
						throw std::logic_error("Left side of array subscript must be a pointer or array type");
					if (right_type.kind != analysis::types::type_node::kind_t::PRIMITIVE)
						throw std::logic_error("Right side of array subscript must be a primitive type");
					auto right_prim_type = std::get<analysis::types::primitive_type>(right_type.value);

					if (!analysis::types::is_integral_type(right_prim_type))
						throw std::logic_error("Right side of array subscript must be an integral type");
					analysis::types::type_node element_type;
					if (left_type.kind == analysis::types::type_node::kind_t::POINTER) {
						auto ptr_type = std::get<analysis::types::pointer_type>(left_type.value);
						element_type = *ptr_type.pointee_type;
					}
					else {
						auto arr_type = std::get<analysis::types::array_type>(left_type.value);
						element_type = *arr_type.element_type;
					}
					auto resolved_element_type = context.global_context->type_system->resolved_type(element_type);
					if (resolved_element_type.kind != analysis::types::type_node::kind_t::PRIMITIVE)
						throw std::logic_error("Element type of array subscript must be a primitive type");
					auto element_prim_type = std::get<analysis::types::primitive_type>(resolved_element_type.value);
					auto element_size = [&]() -> uint32_t {
						switch (analysis::types::to_data_size(element_prim_type)) {
							case machine::data_size_t::BYTE: return 1;
							case machine::data_size_t::WORD: return 2;
							case machine::data_size_t::DWORD: return 4;
						}
						throw std::logic_error("Unknown primitive type");
					}();
					// get the base address into target_reg
					compile_primitive_expression(
						left, context, program, current_scope,
						target_reg, used_regs, modified_regs, statement_index
					);
					if (right.kind == analysis::expressions::expression_node::kind_t::LITERAL) {
						// if the index is a literal, we can do this more efficiently
						const auto& lit = std::get<analysis::expressions::literal_expression>(right.value);
						if (!analysis::types::is_integral_type(right_prim_type))
							throw std::logic_error("Array index must be an integral literal");
						int32_t index = 0;
						switch (lit.kind) {
							case analysis::expressions::literal_expression::kind_t::CHAR:
								index = static_cast<int32_t>(std::get<char>(lit.value));
								break;
							case analysis::expressions::literal_expression::kind_t::INT:
								index = std::get<int32_t>(lit.value);
								break;
							case analysis::expressions::literal_expression::kind_t::UINT:
								index = static_cast<int32_t>(std::get<uint32_t>(lit.value));
								break;
							case analysis::expressions::literal_expression::kind_t::BOOL:
								index = std::get<bool>(lit.value) ? 1 : 0;
								break;
							default:
								throw std::logic_error("Array index must be an integral literal");
						}
						// move the value from target_reg to itself + index * element_size
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOV,
							assembly::assembly_result(target_reg),
							assembly::assembly_operand({
								analysis::types::to_data_size(element_prim_type),
								assembly::assembly_memory(
									target_reg.id,
									static_cast<int32_t>(index * element_size
									)
								)
							})
						));
						return;
					}
					// get the index into a different register
					machine::register_id index_reg_id = find_free_register(
						used_regs,
						{
							machine::register_id::ebx, machine::register_id::ecx, machine::register_id::eax,
							machine::register_id::edx
						},
						{target_reg.id}
					);
					modified_regs.set(index_reg_id, true);
					used_regs.set(target_reg.id, true);
					bool index_is_used = used_regs.get(index_reg_id);
					if (index_is_used) {
						program.push_back(assembly::assembly_instruction(
							machine::operation::PUSH,
							assembly::assembly_operand{index_reg_id}
						));
					}
					compile_primitive_expression(
						right, context, program, current_scope,
						{index_reg_id, machine::register_access::dword}, used_regs,
						modified_regs, statement_index
					);
					// move the value from target_reg to itself + index_reg * element_size
					program.push_back(assembly::assembly_instruction(
						machine::operation::MOV,
						assembly::assembly_result(target_reg),
						assembly::assembly_operand({
							analysis::types::to_data_size(element_prim_type),
							assembly::assembly_memory(
								target_reg.id, index_reg_id, element_size
							)
						})
					));
					if (index_is_used) {
						program.push_back(assembly::assembly_instruction(
							machine::operation::POP,
							assembly::assembly_result{index_reg_id}
						));
					}
					return;
				}

				if (left_type.kind != analysis::types::type_node::kind_t::PRIMITIVE ||
					right_type.kind != analysis::types::type_node::kind_t::PRIMITIVE) {
					throw std::runtime_error("Binary operator can only be applied to primitive types");
				}
				auto left_prim_type = std::get<analysis::types::primitive_type>(left_type.value);
				auto right_prim_type = std::get<analysis::types::primitive_type>(right_type.value);
				machine::register_t target = {target_reg.id, analysis::types::to_data_size(prim_type)};
				used_regs.set(target_reg.id, false);
				compile_primitive_expression(
					left, context, program, current_scope,
					target, used_regs, modified_regs, statement_index
				);
				// get the value of the right side into a different register
				// find a free register or use ebx (order to check: ebx, ecx, eax, edx)
				machine::register_id right_reg_id = find_free_register(
					used_regs,
					{
						machine::register_id::ebx, machine::register_id::ecx, machine::register_id::eax,
						machine::register_id::edx
					},
					{target_reg.id}
				);
				modified_regs.set(right_reg_id, true);
				used_regs.set(target_reg.id, true);
				bool right_is_used = used_regs.get(right_reg_id);
				if (right_is_used) {
					program.push_back(assembly::assembly_instruction(
						machine::operation::PUSH,
						assembly::assembly_operand{right_reg_id}
					));
				}
				assembly::assembly_program_t right_program;
				compile_primitive_expression(
					right, context, right_program, current_scope, {
						right_reg_id, analysis::types::to_data_size(right_prim_type)
					},
					used_regs, modified_regs, statement_index
				);
				// expand/shrink target and right_reg to the required size
				machine::register_t left_calc_reg = {target_reg.id, analysis::types::to_data_size(prim_type)};
				machine::register_t right_calc_reg = {right_reg_id, analysis::types::to_data_size(prim_type)};
				if (analysis::types::to_data_size(left_prim_type) != analysis::types::to_data_size(prim_type)) {
					// convert left side
					if (analysis::types::is_signed_integral_type(left_prim_type) &&
						analysis::types::to_data_size(left_prim_type) < analysis::types::to_data_size(prim_type)) {
						// sign-extend
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOVSX,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand({target_reg.id, analysis::types::to_data_size(left_prim_type)})
						));
					}
					else {
						// zero-extend or truncate
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOVZX,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand({target_reg.id, analysis::types::to_data_size(left_prim_type)})
						));
					}
				}
				if (analysis::types::to_data_size(right_prim_type) != analysis::types::to_data_size(prim_type)) {
					// convert right side
					if (analysis::types::is_signed_integral_type(right_prim_type) &&
						analysis::types::to_data_size(right_prim_type) < analysis::types::to_data_size(prim_type)) {
						// sign-extend
						right_program.push_back(assembly::assembly_instruction(
							machine::operation::MOVSX,
							assembly::assembly_result(right_calc_reg),
							assembly::assembly_operand({right_reg_id, analysis::types::to_data_size(right_prim_type)})
						));
					}
					else {
						// zero-extend or truncate
						right_program.push_back(assembly::assembly_instruction(
							machine::operation::MOVZX,
							assembly::assembly_result(right_calc_reg),
							assembly::assembly_operand({right_reg_id, analysis::types::to_data_size(right_prim_type)})
						));
					}
				}
				// now perform the operation
				switch (binary.op) {
					case analysis::expressions::binary_expression::operator_t::ADD:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							machine::operation::ADD,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::SUB:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							machine::operation::SUB,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::MUL:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							analysis::types::is_signed_integral_type(prim_type)
							? machine::operation::IMUL
							: machine::operation::MUL,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::DIV:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							analysis::types::is_signed_integral_type(prim_type)
							? machine::operation::IDIV
							: machine::operation::DIV,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::MOD:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							analysis::types::is_signed_integral_type(prim_type)
							? machine::operation::IMOD
							: machine::operation::MOD,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::AND:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							machine::operation::AND,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::OR:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							machine::operation::OR,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::XOR:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							machine::operation::XOR,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::SHL:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							machine::operation::SHL,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::SHR:
						program.insert(program.end(), right_program.begin(), right_program.end());
						program.push_back(assembly::assembly_instruction(
							analysis::types::is_signed_integral_type(prim_type)
							? machine::operation::SAR
							: machine::operation::SHR,
							assembly::assembly_result(left_calc_reg),
							assembly::assembly_operand(right_calc_reg)
						));
						break;
					case analysis::expressions::binary_expression::operator_t::LT:
					case analysis::expressions::binary_expression::operator_t::LTE:
					case analysis::expressions::binary_expression::operator_t::GT:
					case analysis::expressions::binary_expression::operator_t::GTE:
					case analysis::expressions::binary_expression::operator_t::EQ:
					case analysis::expressions::binary_expression::operator_t::NEQ:
					case analysis::expressions::binary_expression::operator_t::LAND:
					case analysis::expressions::binary_expression::operator_t::LOR:
						throw std::runtime_error("Internal error: Comparison operators should be handled earlier");
					case analysis::expressions::binary_expression::operator_t::ASSIGN: {
						used_regs.set(target_reg.id, false);
						assembly::assembly_program_t temp_program;
						auto ref = compile_reference(
							left, context, temp_program, current_scope,
							used_regs, modified_regs, statement_index
						);
						regmask ref_regs = get_containing_regs(ref);
						regmask overlap = ref_regs & used_regs;
						std::vector<machine::register_t> saved_regs;
						// save overlapping registers
						for (const auto r : regmask::USABLE_REGISTERS) {
							if (overlap.get(r) && r != target_reg.id && r != right_reg_id) {
								program.emplace_back(assembly::assembly_instruction(
									machine::operation::PUSH,
									assembly::assembly_operand{r}
								));
								saved_regs.emplace_back(r);
							}
						}
						// insert the temp program now
						program.insert(program.end(), temp_program.begin(), temp_program.end());
						// insert the assignment
						compile_assignment(
							ref,
							left_type,
							right,
							context,
							program,
							current_scope,
							used_regs,
							modified_regs,
							statement_index
						);
						// load the assigned value into target_reg
						if (store_value)
							program.push_back(assembly::assembly_instruction(
								machine::operation::MOV,
								assembly::assembly_result(target),
								assembly::assembly_operand({
									analysis::types::to_data_size(prim_type),
									ref
								})
							));
						// restore saved registers
						for (auto it = saved_regs.rbegin(); it != saved_regs.rend(); ++it) {
							program.emplace_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result{*it}
							));
						}
						break;
					}
				}
				// restore right_reg if needed
				if (right_is_used) {
					program.push_back(assembly::assembly_instruction(
						machine::operation::POP,
						assembly::assembly_result{right_reg_id}
					));
				}
				return;
			}
			case analysis::expressions::expression_node::kind_t::TERNARY:
				throw std::runtime_error("Ternary operator not implemented yet");
			default:
				throw std::runtime_error("Unknown expression type");
		};
	}

	bool contains_side_effects(const analysis::expressions::expression_node& expr) {
		switch (expr.kind) {
			case analysis::expressions::expression_node::kind_t::LITERAL:
			case analysis::expressions::expression_node::kind_t::IDENTIFIER:
				return false;
			case analysis::expressions::expression_node::kind_t::UNARY: {
				const auto& unary = std::get<analysis::expressions::unary_expression>(expr.value);
				if (unary.op == analysis::expressions::unary_expression::operator_t::PRE_INC ||
					unary.op == analysis::expressions::unary_expression::operator_t::PRE_DEC ||
					unary.op == analysis::expressions::unary_expression::operator_t::POST_INC ||
					unary.op == analysis::expressions::unary_expression::operator_t::POST_DEC) {
					return true;
				}
				return contains_side_effects(*unary.operand);
			}
			case analysis::expressions::expression_node::kind_t::BINARY: {
				const auto& binary = std::get<analysis::expressions::binary_expression>(expr.value);
				switch (binary.op) {
					case analysis::expressions::binary_expression::operator_t::ASSIGN:
						return true;
					case analysis::expressions::binary_expression::operator_t::LAND: {
						// if left is a literal false or !true, only check left for side effects
						const auto& left = *binary.left;
						if ((left.kind == analysis::expressions::expression_node::kind_t::LITERAL &&
								!std::get<analysis::expressions::literal_expression>(left.value).get_truthiness()) ||
							(left.kind == analysis::expressions::expression_node::kind_t::UNARY &&
								std::get<analysis::expressions::unary_expression>(left.value).op ==
								analysis::expressions::unary_expression::operator_t::LNOT &&
								std::get<analysis::expressions::unary_expression>(left.value).operand->kind ==
								analysis::expressions::expression_node::kind_t::LITERAL &&
								std::get<analysis::expressions::literal_expression>(
									std::get<analysis::expressions::unary_expression>(left.value).operand->value
								).get_truthiness()
							)) {
							return contains_side_effects(*binary.left);
						}
						break;
					}
					case analysis::expressions::binary_expression::operator_t::LOR: {
						// if left is a literal true or !false, only check left for side effects
						const auto& left = *binary.left;
						if ((left.kind == analysis::expressions::expression_node::kind_t::LITERAL &&
								std::get<analysis::expressions::literal_expression>(left.value).get_truthiness()) ||
							(left.kind == analysis::expressions::expression_node::kind_t::UNARY &&
								std::get<analysis::expressions::unary_expression>(left.value).op ==
								analysis::expressions::unary_expression::operator_t::LNOT &&
								std::get<analysis::expressions::unary_expression>(left.value).operand->kind ==
								analysis::expressions::expression_node::kind_t::LITERAL &&
								!std::get<analysis::expressions::literal_expression>(
									std::get<analysis::expressions::unary_expression>(left.value).operand->value
								).get_truthiness()
							)) {
							return contains_side_effects(*binary.left);
						}
						break;
					}
					default:
						break;
				}
				return contains_side_effects(*binary.left) || contains_side_effects(*binary.right);
			}
			case analysis::expressions::expression_node::kind_t::TERNARY: {
				const auto& ternary = std::get<analysis::expressions::ternary_expression>(expr.value);
				return contains_side_effects(*ternary.condition) ||
					contains_side_effects(*ternary.then_branch) ||
					contains_side_effects(*ternary.else_branch);
			}
			case analysis::expressions::expression_node::kind_t::MEMBER: {
				const auto& member = std::get<analysis::expressions::member_expression>(expr.value);
				return contains_side_effects(*member.object);
			}
			case analysis::expressions::expression_node::kind_t::CALL: {
				// function calls are assumed to have side effects
				return true;
			}
			default:
				throw std::runtime_error("Unknown expression type");
		}
	}
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
	) {
		/*
		 * This may get complicated sometimes, so there will be some comments with a conceptual pseudo-code
		 * For that there is a special notation:
		 * - "[x]" means the value of x (variable, expression, etc.)
		 * - "{cond}" means the evaluation of condition cond (true or false)
		 * - "jump {cond} LABEL skip LABEL2" means a conditional jump to LABEL if cond is true, skip to LABEL2 (recursive call of this function)
		 * - "jump !{cond} LABEL skip LABEL2" means a conditional jump to LABEL if cond is false, skip to LABEL2 (recursive call of this function with invert=!invert)
		 * - "jump {cond} LABEL skip LABEL2 (reset)" is like the above but resets the need to jump to LABEL2 (recursive call of this function with needs_skip=false)
		 * - "jump {cond} LABEL else LABEL2" means a conditional jump to LABEL if cond is true, else jump to LABEL2 (always jumps to one of the two) (recursive call of this function with needs_skip=true)
		 * - "jmp LABEL" means an unconditional jump to LABEL
		 * - "jmp eval {cond} LABEL" means jump to LABEL depending on the evaluation of cond, this differs from the above, it compiles the condition as primitive and tests it
		 * - "LABEL:" means a label definition
		 */
		switch (condition.kind) {
			case analysis::expressions::expression_node::kind_t::LITERAL: {
				const auto& lit = std::get<analysis::expressions::literal_expression>(condition.value);
				if (lit.kind != analysis::expressions::literal_expression::kind_t::BOOL &&
					lit.kind != analysis::expressions::literal_expression::kind_t::UINT &&
					lit.kind != analysis::expressions::literal_expression::kind_t::INT &&
					lit.kind != analysis::expressions::literal_expression::kind_t::CHAR &&
					lit.kind != analysis::expressions::literal_expression::kind_t::ULONG &&
					lit.kind != analysis::expressions::literal_expression::kind_t::LONG &&
					lit.kind != analysis::expressions::literal_expression::kind_t::NULLPTR) {
					throw std::runtime_error("Only boolean or integer literals can be used in conditions");
				}
				bool value = false;
				switch (lit.kind) {
					case analysis::expressions::literal_expression::kind_t::BOOL:
						value = std::get<bool>(lit.value);
						break;
					case analysis::expressions::literal_expression::kind_t::CHAR:
						value = std::get<char>(lit.value) != 0;
						break;
					case analysis::expressions::literal_expression::kind_t::INT:
						value = std::get<int32_t>(lit.value) != 0;
						break;
					case analysis::expressions::literal_expression::kind_t::UINT:
						value = std::get<uint32_t>(lit.value) != 0;
						break;
					case analysis::expressions::literal_expression::kind_t::LONG:
						value = std::get<int64_t>(lit.value) != 0;
						break;
					case analysis::expressions::literal_expression::kind_t::ULONG:
						value = std::get<uint64_t>(lit.value) != 0;
						break;
					case analysis::expressions::literal_expression::kind_t::NULLPTR:
						value = false;
						break;
					default:
						throw std::runtime_error("Unexpected literal type in condition");
				}
				if (invert)
					value = !value;
				if (value) {
					// always jump
					program.push_back(assembly::assembly_instruction(
						machine::operation::JMP,
						assembly::assembly_operand(target_label)
					));
					return conditional_jump_info().as_constant(true);
				}
				else {
					// never jump
					if (needs_skip) {
						program.push_back(assembly::assembly_instruction(
							machine::operation::JMP,
							assembly::assembly_operand(no_jump_label)
						));
					}
					return conditional_jump_info().as_constant(false).with_skip(needs_skip);
				}
			}
			case analysis::expressions::expression_node::kind_t::IDENTIFIER: {
				auto ident = std::get<analysis::expressions::identifier_expression>(condition.value);
				if (!context.variable_storage->is_variable_declared(ident.name)) {
					throw std::runtime_error("Variable not found: " + ident.name);
				}

				auto var_type = ident.get_type(
					*context.variable_storage
				);
				auto resolved_var_type = context.global_context->type_system->resolved_type(var_type);
				if (resolved_var_type.kind != analysis::types::type_node::kind_t::PRIMITIVE &&
					resolved_var_type.kind != analysis::types::type_node::kind_t::POINTER) {
					throw std::runtime_error("Only primitive or pointer types can be used in conditions");
				}
				machine::data_size_t data_size;
				if (resolved_var_type.kind == analysis::types::type_node::kind_t::POINTER) {
					data_size = machine::data_size_t::DWORD; // pointers are always 4 bytes
				}
				else {
					auto prim_type = std::get<analysis::types::primitive_type>(resolved_var_type.value);
					if (!analysis::types::is_integral_type(prim_type) && prim_type != analysis::types::primitive_type::BOOL) {
						throw std::runtime_error("Only integral or boolean types can be used in conditions");
					}
					data_size = analysis::types::to_data_size(prim_type);
				}
				assembly::assembly_memory var_mem{0};
				// check the storage class of the variable
				auto storage_type = context.variable_storage->get_declaring_scope(ident.name)->storage_type;
				if (storage_type == analysis::variables::storage::storage_type_t::Global) {
					throw std::runtime_error("Global variable not allowed");
				}
				if (storage_type == analysis::variables::storage::storage_type_t::Function) {
					auto param_idx = context.current_function_signature->name_index_map.at(ident.name);
					auto param_info = context.current_function_signature->parameters[param_idx];
					var_mem = assembly::assembly_memory(
						machine::register_t{machine::register_id::ebp},
						static_cast<int32_t>(param_info.offset)
					);
				}
				else if (storage_type == analysis::variables::storage::storage_type_t::Block) {
					// get the memory reference of the variable
					auto var_info = current_scope.get_variable(ident.name);
					var_mem = assembly::assembly_memory(
						machine::register_t{machine::register_id::ebp},
						-static_cast<int32_t>(var_info.offset)
					);
				}
				else {
					throw std::runtime_error("Unknown variable storage type");
				}
				// test the variable
				program.push_back(assembly::assembly_instruction(
					machine::operation::TEST,
					assembly::assembly_operand({
						data_size,
						var_mem
					}),
					assembly::assembly_operand({
						data_size,
						var_mem
					})
				));
				program.push_back(assembly::assembly_instruction(
					invert ? machine::operation::JZ : machine::operation::JNZ,
					assembly::assembly_operand(target_label)
				));
				if (needs_skip) {
					program.push_back(assembly::assembly_instruction(
						machine::operation::JMP,
						assembly::assembly_operand(no_jump_label)
					));
				}
				return conditional_jump_info().with_skip(needs_skip);
			}
			case analysis::expressions::expression_node::kind_t::UNARY: {
				const auto& unary = std::get<analysis::expressions::unary_expression>(condition.value);
				switch (unary.op) {
					case analysis::expressions::unary_expression::operator_t::LNOT: {
						// just invert the condition and compile the inner expression
						return compile_conditional_jump(
							*unary.operand, !invert, target_label, no_jump_label,
							needs_skip, context, program, current_scope,
							used_regs, modified_regs, statement_index,
							label_prefix
						);
					}
					case analysis::expressions::unary_expression::operator_t::MINUS:
					case analysis::expressions::unary_expression::operator_t::PLUS: {
						// They do not change the truthiness of the expression, just compile the inner expression
						return compile_conditional_jump(
							*unary.operand, invert, target_label, no_jump_label,
							needs_skip, context, program, current_scope,
							used_regs, modified_regs, statement_index,
							label_prefix
						);
					}
					case analysis::expressions::unary_expression::operator_t::SIZEOF: {
						// sizeof does not make much sense in a condition, but we can handle it anyway,
						// although it seems like it, it actually can be zero (e.g. void* a = malloc(0); if (sizeof(a)) ...)
						// find a free register (order to check: eax, ecx, edx, ebx)
						throw std::runtime_error("Sizeof operator not implemented in conditions yet");
					}
					case analysis::expressions::unary_expression::operator_t::NOT: {
						// if the inner type is a boolean, it is just like LNOT, otherwise we need to test the value
						auto inner_type = context.global_context->type_system->resolved_type(
							unary.operand->get_type(
								*context.variable_storage,
								*context.global_context->function_storage,
								*context.global_context->type_system
							)
						);
						if (inner_type.kind != analysis::types::type_node::kind_t::PRIMITIVE)
							throw std::runtime_error("Only a primitive type can be negated");
						auto inner_prim_type = std::get<analysis::types::primitive_type>(inner_type.value);
						if (inner_prim_type == analysis::types::primitive_type::BOOL) {
							// just like LNOT
							return compile_conditional_jump(
								*unary.operand, !invert, target_label, no_jump_label,
								needs_skip, context, program, current_scope,
								used_regs, modified_regs, statement_index,
								label_prefix
							);
						}
						// otherwise, only if the value is ~0, it is false, everything else is true
						// get the value for ~0
						uint32_t not_zero_value = 0;
						switch (analysis::types::to_data_size(inner_prim_type)) {
							case machine::data_size_t::BYTE: not_zero_value = 0xFF;
								break;
							case machine::data_size_t::WORD: not_zero_value = 0xFFFF;
								break;
							case machine::data_size_t::DWORD: not_zero_value = 0xFFFFFFFF;
								break;
						}
						// that means we need to jump if !(value == ~0)
						return compile_conditional_jump(
							analysis::expressions::expression_node{
								analysis::expressions::binary_expression{
									analysis::expressions::binary_expression::operator_t::EQ,
									unary.operand,
									std::make_shared<analysis::expressions::expression_node>(
										analysis::expressions::literal_expression{
											analysis::expressions::literal_expression::kind_t::UINT,
											not_zero_value
										}
									)
								}
							},
							!invert, target_label, no_jump_label,
							needs_skip, context, program, current_scope,
							used_regs, modified_regs, statement_index,
							label_prefix
						);
					}
					case analysis::expressions::unary_expression::operator_t::DEREFERENCE: {
						// need to compile the dereference and test the result
						auto deref_type = context.global_context->type_system->resolved_type(
							unary.operand->get_type(
								*context.variable_storage,
								*context.global_context->function_storage,
								*context.global_context->type_system
							)
						);
						if (deref_type.kind != analysis::types::type_node::kind_t::POINTER)
							throw std::runtime_error("Only a pointer type can be dereferenced");
						// find a free register (order to check: eax, ecx, edx, ebx)
						machine::register_id addr_reg = find_free_register(
							used_regs,
							{
								machine::register_id::eax, machine::register_id::ecx,
								machine::register_id::edx, machine::register_id::ebx,
							}
						);
						modified_regs.set(addr_reg, true);
						bool addr_was_used = used_regs.get(addr_reg);
						machine::register_access addr_reg_access = machine::register_access::dword;
						if (addr_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::PUSH,
								assembly::assembly_operand{addr_reg}
							));
						}
						used_regs.set(addr_reg, false);
						compile_primitive_expression(
							*unary.operand, context, program, current_scope,
							{addr_reg, addr_reg_access}, used_regs,
							modified_regs, statement_index
						);
						machine::data_size_t data_size;
						auto pointee_type = std::get<analysis::types::pointer_type>(deref_type.value).pointee_type;
						auto resolved_pointee_type = context.global_context->type_system->resolved_type(*pointee_type);
						if (resolved_pointee_type.kind == analysis::types::type_node::kind_t::PRIMITIVE) {
							auto prim_type = std::get<analysis::types::primitive_type>(resolved_pointee_type.value);
							if (!analysis::types::is_integral_type(prim_type) && prim_type != analysis::types::primitive_type::BOOL) {
								throw std::runtime_error("Only integral or boolean types can be used in conditions");
							}
							data_size = analysis::types::to_data_size(prim_type);
						}
						else if (resolved_pointee_type.kind == analysis::types::type_node::kind_t::POINTER) {
							data_size = machine::data_size_t::DWORD; // pointers are always 4 bytes
						}
						else {
							throw std::runtime_error("Only primitive or pointer types can be dereferenced in conditions");
						}
						// now test the value at the address in addr_reg
						program.push_back(assembly::assembly_instruction(
							machine::operation::TEST,
							assembly::assembly_operand({
								data_size,
								assembly::assembly_memory(addr_reg)
							}),
							assembly::assembly_operand({
								data_size,
								assembly::assembly_memory(addr_reg)
							})
						));
						// if addr_reg was used, restore it
						if (addr_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result{addr_reg}
							));
						}
						program.push_back(assembly::assembly_instruction(
							invert ? machine::operation::JZ : machine::operation::JNZ,
							assembly::assembly_operand(target_label)
						));
						if (needs_skip) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::JMP,
								assembly::assembly_operand(no_jump_label)
							));
						}
						return conditional_jump_info().with_skip(needs_skip);
					}
					default:
						// other unary operators are handled below
						break;
				}
				break; // break out to handle other unary operators below
			}
			case analysis::expressions::expression_node::kind_t::MEMBER: {
				std::cerr << "Optimizer warning: Member access in condition, not optimized\n";
				break; // break out to handle member access below
			}
			case analysis::expressions::expression_node::kind_t::BINARY: {
				const auto& binary = std::get<analysis::expressions::binary_expression>(condition.value);
				const auto& left = *binary.left;
				const auto& right = *binary.right;
				switch (binary.op) {
					case analysis::expressions::binary_expression::operator_t::LAND: {
						if (invert) {
							// de Morgan's law: !(A && B) == !A || !B
							// so we can compile !A || !B instead
							return compile_conditional_jump(
								analysis::expressions::expression_node{
									analysis::expressions::binary_expression{
										analysis::expressions::binary_expression::operator_t::LOR,
										std::make_shared<analysis::expressions::expression_node>(
											analysis::expressions::unary_expression{
												analysis::expressions::unary_expression::operator_t::LNOT,
												std::make_shared<analysis::expressions::expression_node>(left)
											}
										),
										std::make_shared<analysis::expressions::expression_node>(
											analysis::expressions::unary_expression{
												analysis::expressions::unary_expression::operator_t::LNOT,
												std::make_shared<analysis::expressions::expression_node>(right)
											}
										)
									}
								},
								false, target_label, no_jump_label,
								needs_skip, context, program, current_scope,
								used_regs, modified_regs, statement_index,
								label_prefix
							);
						}
						// from here on, we know we are not inverted
						if ((left.kind == analysis::expressions::expression_node::kind_t::LITERAL &&
								!std::get<analysis::expressions::literal_expression>(left.value).get_truthiness()) ||
							(left.kind == analysis::expressions::expression_node::kind_t::UNARY &&
								std::get<analysis::expressions::unary_expression>(left.value).op ==
								analysis::expressions::unary_expression::operator_t::LNOT &&
								std::get<analysis::expressions::unary_expression>(left.value).operand->kind ==
								analysis::expressions::expression_node::kind_t::LITERAL &&
								std::get<analysis::expressions::literal_expression>(
									std::get<analysis::expressions::unary_expression>(left.value).operand->value
								).get_truthiness()
							)) {
							// left is always false, but it might have side effects, so we need to evaluate it
							return compile_conditional_jump(
								left, false, target_label, no_jump_label,
								needs_skip, context, program, current_scope,
								used_regs, modified_regs, statement_index,
								label_prefix
							);
						}

						/* left is not constant or true!
						 * left = true & side effects:
						 *   jump !{left} ignored skip NEXT (reset)
						 *   NEXT:
						 *   jump {right} target skip NOJUMP
						 *   -> right info + side effects
						 * left = true & no side effects:
						 *   jump {right} target skip NOJUMP
						 *   -> right info
						 * left not constant:
						 *   jump !{left} NOJUMP skip NEXT (reset)
						 *   NEXT:
						 *   jump {right} target skip NOJUMP
						 *   -> right info + skip + left side effects
						 */
						assembly::assembly_program_t left_program;
						std::string next_label = label_prefix + "_nxt";
						auto left_jump_info = compile_conditional_jump(
							left, true, no_jump_label, next_label,
							false, context, left_program, current_scope,
							used_regs, modified_regs, statement_index,
							label_prefix + "l"
						);
						if (left_jump_info.skip_jump)
							left_program.emplace_back(next_label);
						bool left_inserted = left_jump_info.side_effects || !left_jump_info.constant_condition;
						if (left_inserted) {
							// insert left_program and continue with right
							program.insert(program.end(), left_program.begin(), left_program.end());
						}
						// now compile right
						auto right_jump_info = compile_conditional_jump(
							right, false, target_label, no_jump_label,
							needs_skip, context, program, current_scope,
							used_regs, modified_regs, statement_index,
							left_inserted ? label_prefix + "r" : label_prefix
						);
						right_jump_info.side_effects |= left_jump_info.side_effects;
						right_jump_info.constant_condition &= left_jump_info.constant_condition;
						right_jump_info.skip_jump |= !left_jump_info.constant_condition;
						return right_jump_info;
					}
					case analysis::expressions::binary_expression::operator_t::LOR: {
						if (invert) {
							// de Morgan's law: !(A || B) == !A && !B
							// so we can compile !A && !B instead
							return compile_conditional_jump(
								analysis::expressions::expression_node{
									analysis::expressions::binary_expression{
										analysis::expressions::binary_expression::operator_t::LAND,
										std::make_shared<analysis::expressions::expression_node>(
											analysis::expressions::unary_expression{
												analysis::expressions::unary_expression::operator_t::LNOT,
												std::make_shared<analysis::expressions::expression_node>(left)
											}
										),
										std::make_shared<analysis::expressions::expression_node>(
											analysis::expressions::unary_expression{
												analysis::expressions::unary_expression::operator_t::LNOT,
												std::make_shared<analysis::expressions::expression_node>(right)
											}
										)
									}
								},
								false, target_label, no_jump_label,
								needs_skip, context, program, current_scope,
								used_regs, modified_regs, statement_index,
								label_prefix
							);
						}
						// from here on, we know we are not inverted
						if ((left.kind == analysis::expressions::expression_node::kind_t::LITERAL &&
								std::get<analysis::expressions::literal_expression>(left.value).get_truthiness()) ||
							(left.kind == analysis::expressions::expression_node::kind_t::UNARY &&
								std::get<analysis::expressions::unary_expression>(left.value).op ==
								analysis::expressions::unary_expression::operator_t::LNOT &&
								std::get<analysis::expressions::unary_expression>(left.value).operand->kind ==
								analysis::expressions::expression_node::kind_t::LITERAL &&
								!std::get<analysis::expressions::literal_expression>(
									std::get<analysis::expressions::unary_expression>(left.value).operand->value
								).get_truthiness()
							)) {
							// left is always true, but it might have side effects, so we need to evaluate it
							return compile_conditional_jump(
								left, false, target_label, no_jump_label,
								needs_skip, context, program, current_scope,
								used_regs, modified_regs, statement_index,
								label_prefix
							);
						}
						/* left is not constant or false!
						 * left = false & side effects:
						 *   jump {left} ignored skip NEXT (reset)
						 *   NEXT:
						 *   jump {right} target skip NOJUMP
						 *   -> right info + side effects
						 * left = false & no side effects:
						 *   jump {right} target skip NOJUMP
						 *   -> right info
						 * left not constant:
						 *   jump {left} target skip NEXT (reset)
						 *   NEXT:
						 *   jump {right} target skip NOJUMP
						 *   -> right info + left side effects
						 */
						assembly::assembly_program_t left_program;
						std::string next_label = label_prefix + "_nxt";
						auto left_jump_info = compile_conditional_jump(
							left, false, target_label, next_label,
							false, context, left_program, current_scope,
							used_regs, modified_regs, statement_index,
							label_prefix + "l"
						);
						if (left_jump_info.skip_jump)
							left_program.emplace_back(next_label);
						bool left_inserted = left_jump_info.side_effects || !left_jump_info.constant_condition;
						if (left_inserted) {
							// insert left_program and continue with right
							program.insert(program.end(), left_program.begin(), left_program.end());
						}
						// now compile right
						auto right_jump_info = compile_conditional_jump(
							right, false, target_label, no_jump_label,
							needs_skip, context, program, current_scope,
							used_regs, modified_regs, statement_index,
							left_inserted ? label_prefix + "r" : label_prefix
						);
						right_jump_info.side_effects |= left_jump_info.side_effects;
						right_jump_info.constant_condition &= left_jump_info.constant_condition ||
							right_jump_info.jump_always;
						return right_jump_info;
					}
					case analysis::expressions::binary_expression::operator_t::SUB:
					// is just like != (if they are equal, the subtraction is zero, so the condition is false)
					case analysis::expressions::binary_expression::operator_t::NEQ:
					case analysis::expressions::binary_expression::operator_t::EQ: {
						if (binary.op == analysis::expressions::binary_expression::operator_t::SUB ||
							binary.op == analysis::expressions::binary_expression::operator_t::NEQ) {
							invert = !invert;
						}
						bool left_is_const = left.kind == analysis::expressions::expression_node::kind_t::LITERAL;
						bool right_is_const = right.kind == analysis::expressions::expression_node::kind_t::LITERAL;
						if (left_is_const || right_is_const) {
							// if one side is constant, we can do a subtraction and test the result
							const auto& const_expr = left_is_const ? left : right;
							const auto& var_expr = left_is_const ? right : left;
							auto const_lit = std::get<analysis::expressions::literal_expression>(const_expr.value);
							if (const_lit.kind != analysis::expressions::literal_expression::kind_t::BOOL &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::UINT &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::INT &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::CHAR &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::LONG &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::ULONG &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::NULLPTR) {
								throw std::runtime_error("Only boolean or integer literals can be used in conditions");
							}
							analysis::types::type_node var_type = context.global_context->type_system->resolved_type(
								var_expr.get_type(
									*context.variable_storage,
									*context.global_context->function_storage,
									*context.global_context->type_system
								)
							);
							if (var_type.kind != analysis::types::type_node::kind_t::PRIMITIVE &&
								var_type.kind != analysis::types::type_node::kind_t::POINTER)
								throw std::runtime_error("Only primitive or pointer types can be compared");
							analysis::types::primitive_type var_prim_type;
							if (var_type.kind == analysis::types::type_node::kind_t::PRIMITIVE)
								var_prim_type = std::get<analysis::types::primitive_type>(var_type.value);
							else
								var_prim_type = analysis::types::primitive_type::UINT; // pointers are treated as unsigned integers
							uint32_t const_value = const_lit.as_matching(var_prim_type);
							// find a free register (order to check: eax, ecx, edx, ebx)
							machine::register_id cond_reg_id = find_free_register(
								used_regs,
								{
									machine::register_id::eax, machine::register_id::ecx,
									machine::register_id::edx, machine::register_id::ebx,
								}
							);
							modified_regs.set(cond_reg_id, true);
							bool cond_was_used = used_regs.get(cond_reg_id);
							machine::register_access cond_reg_access = machine::register_access::dword;
							if (var_type.kind == analysis::types::type_node::kind_t::PRIMITIVE) {
								if (var_prim_type == analysis::types::primitive_type::BOOL ||
									var_prim_type == analysis::types::primitive_type::CHAR ||
									var_prim_type == analysis::types::primitive_type::UCHAR) {
									cond_reg_access = machine::register_access::low_byte;
								}
								else if (var_prim_type == analysis::types::primitive_type::SHORT ||
									var_prim_type == analysis::types::primitive_type::USHORT) {
									cond_reg_access = machine::register_access::word;
								}
								else {
									cond_reg_access = machine::register_access::dword;
								}
							}
							auto cond_reg = machine::register_t{cond_reg_id, cond_reg_access};
							if (cond_was_used) {
								program.push_back(assembly::assembly_instruction(
									machine::operation::PUSH,
									assembly::assembly_operand{cond_reg_id}
								));
							}
							used_regs.set(cond_reg_id, false);
							compile_primitive_expression(
								var_expr, context, program, current_scope,
								cond_reg, used_regs, modified_regs,
								statement_index, true
							);
							// compare the register with the constant
							program.push_back(assembly::assembly_instruction(
								machine::operation::CMP,
								assembly::assembly_operand{cond_reg},
								assembly::assembly_operand{static_cast<int32_t>(const_value)}
							));
							// restore cond_reg if needed
							if (cond_was_used) {
								program.push_back(assembly::assembly_instruction(
									machine::operation::POP,
									assembly::assembly_result{cond_reg}
								));
							}
							// now jump if zero/non-zero
							program.push_back(assembly::assembly_instruction(
								invert ? machine::operation::JZ : machine::operation::JNZ,
								assembly::assembly_operand(target_label)
							));
							if (needs_skip) {
								program.push_back(assembly::assembly_instruction(
									machine::operation::JMP,
									assembly::assembly_operand(no_jump_label)
								));
							}
							return conditional_jump_info().with_skip(needs_skip).with_side_effects(true);
						}
						// neither side is constant, compile left and right and compare
						// find two free registers (order to check: eax, ecx, edx, ebx)
						machine::register_id left_reg_id = find_free_register(
							used_regs,
							{
								machine::register_id::eax, machine::register_id::ecx,
								machine::register_id::edx, machine::register_id::ebx,
								machine::register_id::esi, machine::register_id::edi,
							}
						);
						modified_regs.set(left_reg_id, true);
						bool left_was_used = used_regs.get(left_reg_id);
						used_regs.set(left_reg_id, false);
						machine::register_id right_reg_id = find_free_register(
							used_regs,
							{
								machine::register_id::eax, machine::register_id::ecx,
								machine::register_id::edx, machine::register_id::ebx,
								machine::register_id::esi, machine::register_id::edi,
							},
							{left_reg_id} // right reg must be different from left reg
						);
						modified_regs.set(right_reg_id, true);
						bool right_was_used = used_regs.get(right_reg_id);
						used_regs.set(right_reg_id, false);
						machine::register_access left_reg_access = machine::register_access::dword;
						machine::register_access right_reg_access = machine::register_access::dword;
						auto left_type = context.global_context->type_system->resolved_type(
							left.get_type(
								*context.variable_storage,
								*context.global_context->function_storage,
								*context.global_context->type_system
							)
						);
						auto right_type = context.global_context->type_system->resolved_type(
							right.get_type(
								*context.variable_storage,
								*context.global_context->function_storage,
								*context.global_context->type_system
							)
						);
						if (left_type.kind == analysis::types::type_node::kind_t::PRIMITIVE) {
							auto left_prim_type = std::get<analysis::types::primitive_type>(left_type.value);
							if (left_prim_type == analysis::types::primitive_type::BOOL ||
								left_prim_type == analysis::types::primitive_type::CHAR ||
								left_prim_type == analysis::types::primitive_type::UCHAR) {
								left_reg_access = machine::register_access::low_byte;
							}
							else if (left_prim_type == analysis::types::primitive_type::SHORT ||
								left_prim_type == analysis::types::primitive_type::USHORT) {
								left_reg_access = machine::register_access::word;
							}
							else {
								left_reg_access = machine::register_access::dword;
							}
						}
						if (right_type.kind == analysis::types::type_node::kind_t::PRIMITIVE) {
							auto right_prim_type = std::get<analysis::types::primitive_type>(right_type.value);
							if (right_prim_type == analysis::types::primitive_type::BOOL ||
								right_prim_type == analysis::types::primitive_type::CHAR ||
								right_prim_type == analysis::types::primitive_type::UCHAR) {
								right_reg_access = machine::register_access::low_byte;
							}
							else if (right_prim_type == analysis::types::primitive_type::SHORT ||
								right_prim_type == analysis::types::primitive_type::USHORT) {
								right_reg_access = machine::register_access::word;
							}
							else {
								right_reg_access = machine::register_access::dword;
							}
						}
						auto left_reg = machine::register_t{left_reg_id, left_reg_access};
						auto right_reg = machine::register_t{right_reg_id, right_reg_access};
						if (left_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::PUSH,
								assembly::assembly_operand{left_reg_id}
							));
						}
						if (right_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::PUSH,
								assembly::assembly_operand{right_reg_id}
							));
						}
						compile_primitive_expression(
							left, context, program, current_scope,
							left_reg, used_regs, modified_regs,
							statement_index, true
						);
						used_regs.set(left_reg_id, true); // left_reg is now used
						compile_primitive_expression(
							right, context, program, current_scope,
							right_reg, used_regs, modified_regs,
							statement_index, true
						);
						// compare the two registers
						program.push_back(assembly::assembly_instruction(
							machine::operation::CMP,
							assembly::assembly_operand{left_reg},
							assembly::assembly_operand{right_reg}
						));
						// restore registers if needed
						if (right_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result{right_reg}
							));
						}
						if (left_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result{left_reg}
							));
						}
						// finally do the jump
						program.push_back(assembly::assembly_instruction(
							invert ? machine::operation::JZ : machine::operation::JNZ,
							assembly::assembly_operand(target_label)
						));
						if (needs_skip) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::JMP,
								assembly::assembly_operand(no_jump_label)
							));
						}
						return conditional_jump_info().with_skip(needs_skip).with_side_effects(true);
					}
					case analysis::expressions::binary_expression::operator_t::GT:
					case analysis::expressions::binary_expression::operator_t::GTE:
					case analysis::expressions::binary_expression::operator_t::LT:
					case analysis::expressions::binary_expression::operator_t::LTE: {
						// check that both sides are primitive types
						auto left_type = context.global_context->type_system->resolved_type(
							left.get_type(
								*context.variable_storage,
								*context.global_context->function_storage,
								*context.global_context->type_system
							)
						);
						auto right_type = context.global_context->type_system->resolved_type(
							right.get_type(
								*context.variable_storage,
								*context.global_context->function_storage,
								*context.global_context->type_system
							)
						);
						if (left_type.kind != analysis::types::type_node::kind_t::PRIMITIVE ||
							right_type.kind != analysis::types::type_node::kind_t::PRIMITIVE)
							throw std::runtime_error("Only primitive types can be compared");
						auto left_prim_type = std::get<analysis::types::primitive_type>(left_type.value);
						auto right_prim_type = std::get<analysis::types::primitive_type>(right_type.value);
						if (!analysis::types::is_integral_type(left_prim_type) ||
							!analysis::types::is_integral_type(right_prim_type))
							throw std::runtime_error("Only integral types can be compared");
						// check if one side is constant
						bool left_is_const = left.kind == analysis::expressions::expression_node::kind_t::LITERAL;
						bool right_is_const = right.kind == analysis::expressions::expression_node::kind_t::LITERAL;
						if (left_is_const || right_is_const) {
							// if one side is constant, we can do a subtraction and test the result
							const auto& const_expr = left_is_const ? left : right;
							const auto& var_expr = left_is_const ? right : left;
							const auto& var_prim_type = left_is_const ? right_prim_type : left_prim_type;
							auto const_lit = std::get<analysis::expressions::literal_expression>(const_expr.value);
							if (const_lit.kind != analysis::expressions::literal_expression::kind_t::UINT &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::INT &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::CHAR &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::LONG &&
								const_lit.kind != analysis::expressions::literal_expression::kind_t::ULONG) {
								throw std::runtime_error("Only integer literals can be used in conditions");
							}
							bool signed_comparison = analysis::types::is_signed_integral_type(var_prim_type);
							uint32_t const_value = const_lit.as_matching(var_prim_type);
							// find a free register (order to check: eax, ecx, edx, ebx)
							machine::register_id var_reg_id = find_free_register(
								used_regs,
								{
									machine::register_id::eax, machine::register_id::ecx,
									machine::register_id::edx, machine::register_id::ebx,
									machine::register_id::esi, machine::register_id::edi,
								}
							);
							modified_regs.set(var_reg_id, true);
							bool var_was_used = used_regs.get(var_reg_id);
							machine::register_access var_reg_access = machine::register_access::dword;
							if (var_prim_type == analysis::types::primitive_type::BOOL ||
								var_prim_type == analysis::types::primitive_type::CHAR ||
								var_prim_type == analysis::types::primitive_type::UCHAR) {
								var_reg_access = machine::register_access::low_byte;
							}
							else if (var_prim_type == analysis::types::primitive_type::SHORT ||
								var_prim_type == analysis::types::primitive_type::USHORT) {
								var_reg_access = machine::register_access::word;
							}
							else {
								var_reg_access = machine::register_access::dword;
							}
							auto var_reg = machine::register_t{var_reg_id, var_reg_access};
							if (var_was_used) {
								program.push_back(assembly::assembly_instruction(
									machine::operation::PUSH,
									assembly::assembly_operand{var_reg_id}
								));
							}
							used_regs.set(var_reg_id, false);
							compile_primitive_expression(
								var_expr, context, program, current_scope,
								var_reg, used_regs, modified_regs,
								statement_index, true
							);
							// compare the register with the constant
							program.push_back(assembly::assembly_instruction(
								machine::operation::CMP,
								assembly::assembly_operand{var_reg},
								assembly::assembly_operand{static_cast<int32_t>(const_value)}
							));
							machine::operation jump_op;
							if (left_is_const)
								invert = !invert; // reverse the operation if the constant is on the left (because we do var - const)
							switch (binary.op) {
								case analysis::expressions::binary_expression::operator_t::GT:
									jump_op = machine::operation::JG;
									break;
								case analysis::expressions::binary_expression::operator_t::GTE:
									jump_op = machine::operation::JGE;
									break;
								case analysis::expressions::binary_expression::operator_t::LT:
									jump_op = machine::operation::JL;
									break;
								case analysis::expressions::binary_expression::operator_t::LTE:
									jump_op = machine::operation::JLE;
									break;
								default:
									throw std::runtime_error("Internal compiler error: invalid comparison operator");
							}
							if (invert) {
								// invert the jump operation
								switch (jump_op) {
									case machine::operation::JG:
										jump_op = machine::operation::JLE;
										break;
									case machine::operation::JGE:
										jump_op = machine::operation::JL;
										break;
									case machine::operation::JL:
										jump_op = machine::operation::JGE;
										break;
									case machine::operation::JLE:
										jump_op = machine::operation::JG;
										break;
									default:
										throw std::runtime_error("Internal compiler error: invalid jump operation");
								}
							}
							if (!signed_comparison) {
								// use unsigned jumps for unsigned comparisons
								switch (jump_op) {
									case machine::operation::JG:
										jump_op = machine::operation::JA;
										break;
									case machine::operation::JGE:
										jump_op = machine::operation::JAE;
										break;
									case machine::operation::JL:
										jump_op = machine::operation::JB;
										break;
									case machine::operation::JLE:
										jump_op = machine::operation::JBE;
										break;
									default:
										throw std::runtime_error("Internal compiler error: invalid jump operation");
								}
							}
							// restore var_reg if needed
							if (var_was_used) {
								program.push_back(assembly::assembly_instruction(
									machine::operation::POP,
									assembly::assembly_result{var_reg}
								));
							}
							// finally, the jump
							program.push_back(assembly::assembly_instruction(
								jump_op,
								assembly::assembly_operand(target_label)
							));
							if (needs_skip) {
								program.push_back(assembly::assembly_instruction(
									machine::operation::JMP,
									assembly::assembly_operand(no_jump_label)
								));
							}
							return conditional_jump_info().with_skip(needs_skip).with_side_effects(true);
						}
						bool left_signed = analysis::types::is_signed_integral_type(left_prim_type);
						bool right_signed = analysis::types::is_signed_integral_type(right_prim_type);
						bool signed_comparison = left_signed || right_signed;
						// neither side is constant, compile left and right and compare
						// find two free registers
						machine::register_id left_reg_id = find_free_register(
							used_regs,
							{
								machine::register_id::eax, machine::register_id::ecx,
								machine::register_id::edx, machine::register_id::ebx,
								machine::register_id::esi, machine::register_id::edi,
							}
						);
						modified_regs.set(left_reg_id, true);
						bool left_was_used = used_regs.get(left_reg_id);
						used_regs.set(left_reg_id, false);
						machine::register_id right_reg_id = find_free_register(
							used_regs,
							{
								machine::register_id::eax, machine::register_id::ecx,
								machine::register_id::edx, machine::register_id::ebx,
								machine::register_id::esi, machine::register_id::edi,
							},
							{left_reg_id} // right reg must be different from left reg
						);
						modified_regs.set(right_reg_id, true);
						bool right_was_used = used_regs.get(right_reg_id);
						used_regs.set(right_reg_id, false);
						machine::register_access left_reg_access = machine::register_access::dword;
						machine::register_access right_reg_access = machine::register_access::dword;
						if (left_prim_type == analysis::types::primitive_type::BOOL ||
							left_prim_type == analysis::types::primitive_type::CHAR ||
							left_prim_type == analysis::types::primitive_type::UCHAR) {
							left_reg_access = machine::register_access::low_byte;
						}
						else if (left_prim_type == analysis::types::primitive_type::SHORT ||
							left_prim_type == analysis::types::primitive_type::USHORT) {
							left_reg_access = machine::register_access::word;
						}
						else {
							left_reg_access = machine::register_access::dword;
						}
						if (right_prim_type == analysis::types::primitive_type::BOOL ||
							right_prim_type == analysis::types::primitive_type::CHAR ||
							right_prim_type == analysis::types::primitive_type::UCHAR) {
							right_reg_access = machine::register_access::low_byte;
						}
						else if (right_prim_type == analysis::types::primitive_type::SHORT ||
							right_prim_type == analysis::types::primitive_type::USHORT) {
							right_reg_access = machine::register_access::word;
						}
						else {
							right_reg_access = machine::register_access::dword;
						}
						auto left_reg = machine::register_t{left_reg_id, left_reg_access};
						auto right_reg = machine::register_t{right_reg_id, right_reg_access};
						if (left_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::PUSH,
								assembly::assembly_operand{left_reg_id}
							));
						}
						if (right_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::PUSH,
								assembly::assembly_operand{right_reg_id}
							));
						}
						compile_primitive_expression(
							left, context, program, current_scope,
							left_reg, used_regs, modified_regs,
							statement_index, true
						);
						used_regs.set(left_reg_id, true); // left_reg is now used
						compile_primitive_expression(
							right, context, program, current_scope,
							right_reg, used_regs, modified_regs,
							statement_index, true
						);
						// compare the two registers
						program.push_back(assembly::assembly_instruction(
							machine::operation::CMP,
							assembly::assembly_operand{left_reg},
							assembly::assembly_operand{right_reg}
						));
						machine::operation jump_op;
						switch (binary.op) {
							case analysis::expressions::binary_expression::operator_t::GT:
								jump_op = machine::operation::JG;
								break;
							case analysis::expressions::binary_expression::operator_t::GTE:
								jump_op = machine::operation::JGE;
								break;
							case analysis::expressions::binary_expression::operator_t::LT:
								jump_op = machine::operation::JL;
								break;
							case analysis::expressions::binary_expression::operator_t::LTE:
								jump_op = machine::operation::JLE;
								break;
							default:
								throw std::runtime_error("Internal compiler error: invalid comparison operator");
						}
						if (invert) {
							// invert the jump operation
							switch (jump_op) {
								case machine::operation::JG:
									jump_op = machine::operation::JLE;
									break;
								case machine::operation::JGE:
									jump_op = machine::operation::JL;
									break;
								case machine::operation::JL:
									jump_op = machine::operation::JGE;
									break;
								case machine::operation::JLE:
									jump_op = machine::operation::JG;
									break;
								default:
									throw std::runtime_error("Internal compiler error: invalid jump operation");
							}
						}
						if (!signed_comparison) {
							// use unsigned jumps for unsigned comparisons
							switch (jump_op) {
								case machine::operation::JG:
									jump_op = machine::operation::JA;
									break;
								case machine::operation::JGE:
									jump_op = machine::operation::JAE;
									break;
								case machine::operation::JL:
									jump_op = machine::operation::JB;
									break;
								case machine::operation::JLE:
									jump_op = machine::operation::JBE;
									break;
								default:
									throw std::runtime_error("Internal compiler error: invalid jump operation");
							}
						}
						// restore registers if needed
						if (right_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result{right_reg}
							));
						}
						if (left_was_used) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::POP,
								assembly::assembly_result{left_reg}
							));
						}
						// finally, do the jump
						program.push_back(assembly::assembly_instruction(
							jump_op,
							assembly::assembly_operand(target_label)
						));
						if (needs_skip) {
							program.push_back(assembly::assembly_instruction(
								machine::operation::JMP,
								assembly::assembly_operand(no_jump_label)
							));
						}
						return conditional_jump_info().with_skip(needs_skip).with_side_effects(true);
					}
					default:
						// other binary operators have no supported optimizations
						break;
				}
			}
			case analysis::expressions::expression_node::kind_t::TERNARY:
				break; // TODO: handle ternary expressions
			default:
				break; // other expressions are handled below
		}
		// for other expressions, compile to a register and test
		// find a free register (order to check: eax, ecx, edx, ebx)
		machine::register_id cond_reg_id = find_free_register(
			used_regs,
			{
				machine::register_id::eax, machine::register_id::ecx,
				machine::register_id::edx, machine::register_id::ebx,
			}
		);
		modified_regs.set(cond_reg_id, true);
		bool cond_was_used = used_regs.get(cond_reg_id);
		machine::register_access cond_reg_access = machine::register_access::dword;
		auto cond_type = context.global_context->type_system->resolved_type(
			condition.get_type(
				*context.variable_storage,
				*context.global_context->function_storage,
				*context.global_context->type_system
			)
		);
		if (cond_type.kind == analysis::types::type_node::kind_t::PRIMITIVE) {
			auto cond_prim_type = std::get<analysis::types::primitive_type>(cond_type.value);
			if (cond_prim_type == analysis::types::primitive_type::BOOL ||
				cond_prim_type == analysis::types::primitive_type::CHAR ||
				cond_prim_type == analysis::types::primitive_type::UCHAR) {
				cond_reg_access = machine::register_access::low_byte;
			}
			else if (cond_prim_type == analysis::types::primitive_type::SHORT ||
				cond_prim_type == analysis::types::primitive_type::USHORT) {
				cond_reg_access = machine::register_access::word;
			}
			else {
				cond_reg_access = machine::register_access::dword;
			}
		}
		auto cond_reg = machine::register_t{cond_reg_id, cond_reg_access};
		if (cond_was_used) {
			program.push_back(assembly::assembly_instruction(
				machine::operation::PUSH,
				assembly::assembly_operand{cond_reg_id}
			));
		}
		used_regs.set(cond_reg_id, false);
		compile_primitive_expression(
			condition, context, program, current_scope,
			cond_reg, used_regs, modified_regs,
			statement_index, true
		);
		// test the condition
		program.push_back(assembly::assembly_instruction(
			machine::operation::TEST,
			assembly::assembly_operand{cond_reg},
			assembly::assembly_operand{cond_reg}
		));
		program.push_back(assembly::assembly_instruction(
			invert ? machine::operation::JZ : machine::operation::JNZ,
			assembly::assembly_operand(target_label)
		));
		if (needs_skip) {
			program.push_back(assembly::assembly_instruction(
				machine::operation::JMP,
				assembly::assembly_operand(no_jump_label)
			));
		}
		// restore cond_reg if needed
		if (cond_was_used) {
			program.push_back(assembly::assembly_instruction(
				machine::operation::POP,
				assembly::assembly_result{cond_reg}
			));
		}
		bool side_effects = contains_side_effects(condition);
		return conditional_jump_info().with_skip(needs_skip).with_side_effects(side_effects);
	}

	void compile_block_statement(
		const analysis::statements::block_statement& block,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		std::string label_prefix
	) {
		for (uint32_t i = 0; i < block.statements.size(); ++i) {
			compile_statement(
				*block.statements[i], context, program, current_scope,
				used_regs, modified_regs, i, label_prefix
			);
		}
	}

	void compile_declaration_statement(
		const analysis::statements::declaration_statement& decl,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		std::string label_prefix
	) {
		switch (decl.kind) {
			case analysis::statements::declaration_statement::kind_t::VARIABLE: {
				const auto& var_decl = std::get<analysis::statements::declaration_variable_statement>(decl.declaration);
				/*program.emplace_back(assembly::assembly_instruction{
					machine::operation::SUB,
					assembly::assembly_result{machine::register_id::esp},
					assembly::assembly_operand{
						static_cast<int32_t>(context.global_context->type_system->get_type_size(var_decl.type))
					}
				});*/
				context.variable_storage->declare_variable(
					var_decl.name,
					var_decl.type,
					true
				);
				if (var_decl.initializer.has_value()) {
					compile_assignment(
						assembly::assembly_memory(
							machine::register_id::ebp,
							-static_cast<int32_t>(current_scope.get_variable(var_decl.name).offset)
						),
						var_decl.type,
						*var_decl.initializer,
						context,
						program,
						current_scope,
						used_regs,
						modified_regs,
						statement_index
					);
				}
				break;
			}
			case analysis::statements::declaration_statement::kind_t::FUNCTION:
				throw std::runtime_error("Function declaration not allowed here");
			case analysis::statements::declaration_statement::kind_t::STRUCT:
				throw std::runtime_error("Struct declaration not allowed here");
			case analysis::statements::declaration_statement::kind_t::TYPEDEF:
				throw std::runtime_error("Typedef declaration not allowed here");
			case analysis::statements::declaration_statement::kind_t::UNION:
				throw std::runtime_error("Union declaration not allowed here");
		}
	}
	void compile_if_statement(
		const analysis::statements::if_statement& if_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		std::string label_prefix
	) {
		bool all_return = true;
		std::string end_label = label_prefix + std::to_string(statement_index) + "_if_end";
		for (size_t i = 0; i < if_stmt.clauses.size(); ++i) {
			bool is_last_clause = (i == if_stmt.clauses.size() - 1);
			std::string next_label = is_last_clause
				? end_label
				: label_prefix + std::to_string(statement_index) + "_if_clause_" + std::to_string(i + 1);
			const auto& clause = if_stmt.clauses[i];
			bool constant_condition = false;
			bool constant_value = false;
			if (clause.condition.has_value()) {
				// compile the condition
				// if false jump to next clause
				std::string body_label = label_prefix + std::to_string(statement_index) + "_if_clause_" + std::to_string(i) +
					"_body";
				assembly::assembly_program_t clause_program;
				auto info = compile_conditional_jump(
					*clause.condition, true, next_label, body_label,
					false, context, clause_program, current_scope, used_regs, modified_regs, statement_index,
					label_prefix + "_if" + std::to_string(statement_index) + "_c" + std::to_string(i) + "_"
				);
				if (info.skip_jump) {
					// we need to add the body label
					clause_program.emplace_back(body_label);
				}
				constant_condition = info.constant_condition;
				constant_value = !info.jump_always;
				if (info.side_effects || !constant_condition) {
					// if there are side effects, we need to keep the generated code
					program.insert(program.end(), clause_program.begin(), clause_program.end());
				}
			}
			else if (!is_last_clause) {
				// else clause must be the last one
				throw std::runtime_error("Else clause must be the last clause in an if statement");
			}
			if (!constant_condition || constant_value) {
				// compile the body
				// first create a new scope
				const child_scope_key child_scope_key{statement_index, static_cast<uint32_t>(i)};
				auto& child_scope = current_scope.children.at(child_scope_key);
				auto variable_storage = std::make_shared<analysis::variables::storage>(
					analysis::variables::storage::storage_type_t::Block,
					context.variable_storage
				);
				scoped_compilation_context child_context{
					&context,
					variable_storage,
				};
				compile_block_statement(
					clause.body, child_context, program, *child_scope.child,
					used_regs, modified_regs,
					label_prefix + "if" + std::to_string(statement_index) + "_c" + std::to_string(i) + "_"
				);
				bool clause_returns = child_scope.child->all_paths_return;
				all_return &= clause_returns;
				// jump to the end
				if (!is_last_clause && !clause_returns) {
					program.push_back(assembly::assembly_instruction(
						machine::operation::JMP,
						assembly::assembly_operand{end_label}
					));
				}
			}
			// next clause label
			if (!is_last_clause) {
				program.emplace_back(next_label);
			}
			if (constant_condition && constant_value) {
				// the condition is always true, no need to compile further clauses
				break;
			}
		}
		if (!all_return) {
			// end label
			program.emplace_back(end_label);
		}
	}
	void compile_while_statement(
		const analysis::statements::while_statement& while_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		std::string label_prefix
	) {
		if (while_stmt.is_do_while)
			throw std::runtime_error("Do-while loops not implemented yet");
		std::string start_label = label_prefix + std::to_string(statement_index) + "_while_start";
		std::string end_label = label_prefix + std::to_string(statement_index) + "_while_end";
		program.emplace_back(start_label);
		// compile the condition
		auto cond_reg = find_free_register(
			used_regs,
			{
				machine::register_id::eax, machine::register_id::ebx, machine::register_id::ecx,
				machine::register_id::edx
			}
		);
		modified_regs.set(cond_reg, true);
		bool cond_was_used = used_regs.get(cond_reg);
		if (cond_was_used) {
			program.push_back(assembly::assembly_instruction(
				machine::operation::PUSH,
				assembly::assembly_operand{cond_reg}
			));
		}
		used_regs.set(cond_reg, false);
		compile_primitive_expression(
			while_stmt.condition, context, program, current_scope,
			{cond_reg, machine::register_access::dword}, used_regs, modified_regs,
			statement_index, true
		);
		// test the condition
		program.push_back(assembly::assembly_instruction(
			machine::operation::TEST,
			assembly::assembly_operand{cond_reg},
			assembly::assembly_operand{cond_reg}
		));
		program.push_back(assembly::assembly_instruction(
			machine::operation::JZ,
			assembly::assembly_operand{end_label}
		));
		// compile the body
		// first create a new scope
		const child_scope_key child_scope_key{statement_index, 0};
		auto& child_scope = current_scope.children.at(child_scope_key);
		auto variable_storage = std::make_shared<analysis::variables::storage>(
			analysis::variables::storage::storage_type_t::Block,
			context.variable_storage
		);
		scoped_compilation_context child_context{
			&context,
			variable_storage,
		};
		compile_block_statement(
			while_stmt.body, child_context, program, *child_scope.child,
			used_regs, modified_regs, label_prefix + "w" + std::to_string(statement_index) + "_"
		);
		// jump back to the start
		program.push_back(assembly::assembly_instruction(
			machine::operation::JMP,
			assembly::assembly_operand{start_label}
		));
		// end label
		program.emplace_back(end_label);
		// restore condition register if needed
		if (cond_was_used) {
			program.push_back(assembly::assembly_instruction(
				machine::operation::POP,
				assembly::assembly_result{cond_reg}
			));
		}
	}
	void compile_return_statement(
		const analysis::statements::return_statement& return_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		std::string label_prefix
	) {
		if (return_stmt.value.has_value()) {
			// we need to return a value
			// the return value will be stored at [ebp + 8] (overwriting the argument space)

			if (context.current_function_signature->return_type.kind == analysis::types::type_node::kind_t::PRIMITIVE &&
				std::get<analysis::types::primitive_type>(context.current_function_signature->return_type.value) ==
				analysis::types::primitive_type::VOID) {
				throw std::runtime_error("Function has void return type but return statement has a value");
			}

			auto& ret_type = context.current_function_signature->return_type;
			const auto& resolved_ret_type = context.global_context->type_system->resolved_type(ret_type);
			const auto& expr_val_type = return_stmt.value->get_type(
				*context.variable_storage,
				*context.global_context->function_storage,
				*context.global_context->type_system
			);
			const auto& resolved_expr_val_type = context.global_context->type_system->resolved_type(expr_val_type);
			if (resolved_ret_type.kind != resolved_expr_val_type.kind) {
				throw std::runtime_error("Return type does not match function return type");
			}
			if (resolved_ret_type.kind == analysis::types::type_node::kind_t::PRIMITIVE ||
				resolved_ret_type.kind == analysis::types::type_node::kind_t::POINTER) {
				machine::data_size_t ret_size, expr_size;
				bool is_signed = false;
				if (resolved_ret_type.kind == analysis::types::type_node::kind_t::PRIMITIVE) {
					auto ret_prim_type = std::get<analysis::types::primitive_type>(resolved_ret_type.value);
					auto expr_prim_type = std::get<analysis::types::primitive_type>(resolved_expr_val_type.value);
					if (!analysis::types::can_implicitly_convert(expr_prim_type, ret_prim_type)) {
						throw std::runtime_error("Cannot implicitly convert return value to function return type");
					}
					ret_size = analysis::types::to_data_size(ret_prim_type);
					expr_size = analysis::types::to_data_size(expr_prim_type);
					is_signed = analysis::types::is_signed_integral_type(expr_prim_type) &&
						analysis::types::is_signed_integral_type(ret_prim_type);
				}
				else {
					// both are pointers
					ret_size = machine::data_size_t::DWORD;
					expr_size = machine::data_size_t::DWORD;
				}
				// get the return value into a free register
				machine::register_id ret_reg_id = find_free_register(
					used_regs,
					{
						machine::register_id::eax, machine::register_id::ebx, machine::register_id::ecx,
						machine::register_id::edx
					}
				);
				modified_regs.set(ret_reg_id, true);
				bool was_used = used_regs.get(ret_reg_id);
				if (was_used) {
					program.push_back(assembly::assembly_instruction(
						machine::operation::PUSH,
						assembly::assembly_operand{ret_reg_id}
					));
				}
				used_regs.set(ret_reg_id, false);
				compile_primitive_expression(
					*return_stmt.value, context, program, current_scope,
					{ret_reg_id, expr_size}, used_regs, modified_regs,
					statement_index, true
				);
				// move the return value into [ebp + 8]
				if (ret_size != expr_size) {
					if (is_signed) {
						// sign-extend
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOVSX,
							assembly::assembly_result({ret_reg_id, ret_size}),
							assembly::assembly_operand({ret_reg_id, expr_size})
						));
					}
					else {
						// zero-extend or truncate
						program.push_back(assembly::assembly_instruction(
							machine::operation::MOVZX,
							assembly::assembly_result({ret_reg_id, ret_size}),
							assembly::assembly_operand({ret_reg_id, expr_size})
						));
					}
				}
				program.push_back(assembly::assembly_instruction(
					machine::operation::MOV,
					assembly::assembly_result({
						ret_size,
						assembly::assembly_memory(machine::register_id::ebp, 8)
					}),
					assembly::assembly_operand{{ret_reg_id, ret_size}}
				));
				if (was_used) {
					program.push_back(assembly::assembly_instruction(
						machine::operation::POP,
						assembly::assembly_result{ret_reg_id}
					));
				}
			}
			else {
				throw std::runtime_error("Return type not implemented yet");
			}
		}
		// jump to the function end
		if (!context.current_function_signature->name.has_value())
			throw std::runtime_error("Internal error: current function has no name");
		program.push_back(assembly::assembly_instruction(
			machine::operation::JMP,
			assembly::assembly_operand{"func_" + *context.current_function_signature->name + "_end"}
		));
	}
	void compile_expression_statement(
		const analysis::expressions::expression_node& expr_stmt,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		std::string label_prefix
	) {
		// we don't care about the result, so we can use any register and not save it
		machine::register_id target_reg_id = find_free_register(
			used_regs,
			{
				machine::register_id::ebx, machine::register_id::ecx, machine::register_id::eax,
				machine::register_id::edx
			}
		);
		modified_regs.set(target_reg_id, true);
		bool was_used = used_regs.get(target_reg_id);
		if (was_used) {
			program.push_back(assembly::assembly_instruction(
				machine::operation::PUSH,
				assembly::assembly_operand{target_reg_id}
			));
		}
		used_regs.set(target_reg_id, false);
		compile_primitive_expression(
			expr_stmt, context, program, current_scope,
			{target_reg_id, machine::register_access::dword}, used_regs, modified_regs,
			statement_index, false
		);
		if (was_used) {
			program.push_back(assembly::assembly_instruction(
				machine::operation::POP,
				assembly::assembly_result{target_reg_id}
			));
		}
	}
	void compile_statement(
		const analysis::statements::statement_node& statement,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		regmask used_regs,
		regmask& modified_regs,
		uint32_t statement_index,
		std::string label_prefix
	) {
		switch (statement.kind) {
			case analysis::statements::statement_node::kind_t::BLOCK: {
				// get the child scope
				// the key will be the statement index and 0 (only statements with multiple children have multiple sub-scopes)
				const child_scope_key key{statement_index, 0};
				auto& child_scope = current_scope.children.at(key);
				// also we need to create a new scoped context
				// for this we need a new variable storage that has the current one as parent
				auto variable_storage = std::make_shared<analysis::variables::storage>(
					analysis::variables::storage::storage_type_t::Block,
					context.variable_storage
				);
				scoped_compilation_context child_context{
					&context,
					variable_storage,
				};
				compile_block_statement(
					std::get<analysis::statements::block_statement>(statement.value),
					child_context, program, *child_scope.child, used_regs, modified_regs,
					label_prefix + "b" + std::to_string(statement_index) + "_"
				);
				break;
			}
			case analysis::statements::statement_node::kind_t::DECLARATION:
				compile_declaration_statement(
					std::get<analysis::statements::declaration_statement>(statement.value),
					context, program, current_scope, used_regs, modified_regs, statement_index, label_prefix
				);
				break;
			case analysis::statements::statement_node::kind_t::IF:
				compile_if_statement(
					std::get<analysis::statements::if_statement>(statement.value),
					context, program, current_scope, used_regs, modified_regs, statement_index, label_prefix
				);
				break;
			case analysis::statements::statement_node::kind_t::WHILE:
				compile_while_statement(
					std::get<analysis::statements::while_statement>(statement.value),
					context, program, current_scope, used_regs, modified_regs, statement_index, label_prefix
				);
				break;
			case analysis::statements::statement_node::kind_t::RETURN:
				compile_return_statement(
					std::get<analysis::statements::return_statement>(statement.value),
					context, program, current_scope, used_regs, modified_regs, statement_index, label_prefix
				);
				break;
			case analysis::statements::statement_node::kind_t::EXPRESSION:
				compile_expression_statement(
					std::get<analysis::expressions::expression_node>(statement.value),
					context, program, current_scope, used_regs, modified_regs, statement_index, label_prefix
				);
				break;
			default:
				throw std::runtime_error("Unknown statement type");
		}
	}

	void Compiler::analyze_program(const ast_program& program) {
		for (const auto& comp : program.body) {
			if (std::holds_alternative<ast_statement_function_declaration>(comp)) {
				const auto& func_decl = std::get<ast_statement_function_declaration>(comp);
				const auto& name = func_decl.name;
				std::vector<analysis::types::type_node> param_types;
				for (const auto& typ : func_decl.parameters | std::views::values) {
					param_types.push_back(analysis::types::type_system::from_ast(*typ));
				}
				auto return_type = analysis::types::type_system::from_ast(*func_decl.return_type);
				m_function_storage->declare_function(name, return_type, param_types, func_decl.body != nullptr);
				if (func_decl.body != nullptr) {
					// add the function to the function list for later compilation
					m_function_declarations.push_back(func_decl);
				}
			}
			else if (std::holds_alternative<ast_statement_type_declaration>(comp)) {
				const auto& type_decl = std::get<ast_statement_type_declaration>(comp);
				const auto& name = type_decl.name;
				const auto& type_node = type_decl.aliased_type;
				m_type_system->declare_initialized_type(name, analysis::types::type_system::from_ast(*type_node));
			}
			else if (std::holds_alternative<ast_statement_variable_declaration>(comp)) {
				// global variable declaration, implemented later
			}
			else if (std::holds_alternative<ast_statement_struct_declaration>(comp)) {
				const auto& struct_decl = std::get<ast_statement_struct_declaration>(comp);
				const auto& name = struct_decl.name;

				if (struct_decl.body == nullptr) {
					// forward declaration
					m_type_system->declare_type(name, analysis::types::type_node::kind_t::STRUCT);
					continue;
				}

				analysis::types::struct_type st;
				st.members.reserve(struct_decl.body->members.size());
				for (const auto& member : struct_decl.body->members) {
					st.members.emplace_back(
						member.name,
						analysis::types::type_system::from_ast(*member.type)
					);
				}
				m_type_system->declare_initialized_type(name, analysis::types::type_node(st));
			}
			else if (std::holds_alternative<ast_statement_union_declaration>(comp)) {
				const auto& union_decl = std::get<ast_statement_union_declaration>(comp);
				const auto& name = union_decl.name;

				if (union_decl.body == nullptr) {
					// forward declaration
					m_type_system->declare_type(name, analysis::types::type_node::kind_t::UNION);
					continue;
				}

				analysis::types::union_type ut;
				ut.members.reserve(union_decl.body->members.size());
				for (const auto& member : union_decl.body->members) {
					ut.members.emplace_back(
						member.name,
						analysis::types::type_system::from_ast(*member.type)
					);
				}
				m_type_system->declare_initialized_type(name, analysis::types::type_node(ut));
			}
			else {
				throw std::runtime_error("Unknown top-level AST component");
			}
		}
	}
	void Compiler::precompile_functions() {
		for (const auto& func_decl : m_function_declarations) {
			if (m_compiled_functions.contains(func_decl.name))
				// already compiled
				continue;
			assembly::assembly_program_t func_program;
			compile_function(func_decl, func_program);
			m_compiled_functions[func_decl.name] = std::move(func_program);
		}
	}
	std::shared_ptr<scope> Compiler::build_function_scope(const ast_statement_function_declaration& func_decl) {
		if (func_decl.body == nullptr) {
			throw std::runtime_error("Function has no body");
		}
		std::shared_ptr<scope> func_scope;
		(void) build_scope(*func_decl.body, func_scope, nullptr);
		return func_scope;
	}
	std::shared_ptr<assembly_scope> Compiler::build_function_assembly_scope(const std::shared_ptr<scope>& func_scope) {
		if (func_scope == nullptr) {
			throw std::runtime_error("Function scope is null");
		}
		compilation_context context;
		context.type_system = m_type_system;
		return func_scope->build_assembly_scope(context, nullptr, 0);
	}
	void Compiler::compile_function(const ast_statement_function_declaration& func_decl,
		assembly::assembly_program_t& out_program) {
		if (func_decl.body == nullptr) {
			throw std::runtime_error("Function has no body");
		}
		const auto& name = func_decl.name;
		// we need to get the function signature, function scope and convert the function body
		auto func_scope = build_function_scope(func_decl);
		auto asm_func_scope = build_function_assembly_scope(func_scope);
		// build the function signature
		function_signature func_sig;
		func_sig.name = name;
		func_sig.return_type = analysis::types::type_system::from_ast(*func_decl.return_type);
		func_sig.parameters.reserve(func_decl.parameters.size());
		for (size_t i = 0; i < func_decl.parameters.size(); ++i) {
			const auto& param = func_decl.parameters[i];
			func_sig.parameters.emplace_back(
				param.first,
				analysis::types::type_system::from_ast(*param.second),
				i
			);
		}
		auto asm_func_sig = func_sig.build_assembly_signature(*m_type_system);
		// compile the function
		compile_function(
			name,
			asm_func_sig,
			asm_func_scope,
			analysis::statements::block_statement::from_ast(*func_decl.body),
			out_program
		);
	}
	void Compiler::compile_function(
		const std::string& func_name,
		const std::shared_ptr<assembly_function_signature>& func_sig,
		const std::shared_ptr<assembly_scope>& func_scope,
		const analysis::statements::block_statement& func_body,
		assembly::assembly_program_t& out_program
	) {
		if (func_sig == nullptr || func_scope == nullptr) {
			throw std::runtime_error("Function signature or scope is null");
		}
		// create the initial used registers mask
		regmask used_regs;
		used_regs.set(machine::register_id::ebp, true);
		used_regs.set(machine::register_id::esp, true);
		// create the initial compilation context
		auto function_variable_storage = std::make_shared<analysis::variables::storage>(
			analysis::variables::storage::storage_type_t::Function,
			this->m_variable_storage
		);
		for (const auto& param : func_sig->parameters) {
			if (param.name.has_value())
				function_variable_storage->declare_variable(
					*param.name,
					param.type,
					true
				);
		}
		auto variable_storage = std::make_shared<analysis::variables::storage>(
			analysis::variables::storage::storage_type_t::Block,
			function_variable_storage
		);
		scoped_compilation_context context{
			std::make_shared<compilation_context>(
				this->m_type_system,
				this->m_function_storage,
				this->m_variable_storage
			),
			variable_storage,
			func_sig
		};

		// compile the function body
		regmask modified_regs;
		std::string label_prefix = "func_" + func_name;
		assembly::assembly_program_t temp_program;
		compile_block_statement(
			func_body, context, temp_program, *func_scope, used_regs,
			modified_regs, label_prefix + "_"
		);

		// function label
		out_program.emplace_back(generate_function_label(func_name));
		// function prologue
		out_program.push_back(assembly::assembly_instruction(
			machine::operation::PUSH,
			assembly::assembly_operand{machine::register_id::ebp}
		));
		out_program.push_back(assembly::assembly_instruction(
			machine::operation::MOV,
			assembly::assembly_result{machine::register_id::ebp},
			assembly::assembly_operand{machine::register_id::esp}
		));
		if (func_scope->cumulative_stack_size > 0) {
			out_program.push_back(assembly::assembly_instruction(
				machine::operation::SUB,
				assembly::assembly_result{machine::register_id::esp},
				assembly::assembly_operand{static_cast<int32_t>(func_scope->cumulative_stack_size)}
			));
		}
		// store modified registers
		std::vector<machine::register_t> saved_regs;
		for (const auto r : regmask::USABLE_REGISTERS) {
			if (modified_regs.get(r)) {
				out_program.emplace_back(assembly::assembly_instruction(
					machine::operation::PUSH,
					assembly::assembly_operand{r}
				));
				saved_regs.emplace_back(r);
			}
		}
		out_program.insert(out_program.end(), temp_program.begin(), temp_program.end());
		// function epilogue
		// label
		out_program.emplace_back("func_" + func_name + "_end");
		// restore modified registers
		for (auto it = saved_regs.rbegin(); it != saved_regs.rend(); ++it) {
			out_program.emplace_back(assembly::assembly_instruction(
				machine::operation::POP,
				assembly::assembly_result{*it}
			));
		}
		// cleanup the stack and return
		out_program.push_back(assembly::assembly_instruction(
			machine::operation::MOV,
			assembly::assembly_result{machine::register_id::esp},
			assembly::assembly_operand{machine::register_id::ebp}
		));
		out_program.push_back(assembly::assembly_instruction(
			machine::operation::POP,
			assembly::assembly_result{machine::register_id::ebp}
		));
		out_program.push_back(assembly::assembly_instruction(
			machine::operation::RET
		));
	}
	void Compiler::register_built_in_function(
		const analysis::functions::function_info& func_info,
		const assembly::assembly_program_t& program
	) {
		assembly::assembly_program_t func_program;
		func_program.reserve(program.size() + 1);
		func_program.push_back(generate_function_label(func_info.name));
		func_program.insert(func_program.end(), program.begin(), program.end());
		// store the function
		m_built_in_functions.emplace(
			func_info.name,
			built_in_function{func_info, func_program}
		);
		m_function_storage->declare_function(
			func_info.name,
			func_info.return_type,
			func_info.parameter_types,
			true
		);
	}
	void Compiler::compile_entry(const std::string& entry_function, assembly::assembly_program_t& out_program) {
		if (!m_function_storage->is_function_declared(entry_function)) {
			throw std::runtime_error("Entry function '" + entry_function + "' is not declared");
		}
		const auto& func_info = m_function_storage->get_function(entry_function);
		if (!func_info.is_defined) {
			throw std::runtime_error("Entry function '" + entry_function + "' is not defined");
		}
		if (func_info.parameter_types.size() != 0) {
			throw std::runtime_error("Entry function '" + entry_function + "' must have no parameters");
		}
		if (func_info.return_type.kind != analysis::types::type_node::kind_t::PRIMITIVE) {
			throw std::runtime_error("Entry function '" + entry_function + "' must have primitive return type");
		}
		auto prim_type = std::get<analysis::types::primitive_type>(func_info.return_type.value);
		if (prim_type != analysis::types::primitive_type::VOID &&
			prim_type != analysis::types::primitive_type::INT) {
			throw std::runtime_error("Entry function '" + entry_function + "' must have void or int return type");
		}
		out_program.emplace_back("__global_entry");
		if (prim_type == analysis::types::primitive_type::INT) {
			// we need to return an int, so reserve space on the stack
			out_program.push_back(assembly::assembly_instruction(
				machine::operation::SUB,
				assembly::assembly_result{machine::register_id::esp},
				assembly::assembly_operand{4}
			));
		}
		out_program.push_back(assembly::assembly_instruction(
			machine::operation::CALL,
			assembly::assembly_operand{generate_function_label(entry_function)}
		));
		if (prim_type != analysis::types::primitive_type::VOID) {
			// move the return value from eax to the reserved space
			out_program.push_back(assembly::assembly_instruction(
				machine::operation::OUT,
				assembly::assembly_operand{
					assembly::assembly_memory_pointer{
						machine::data_size_t::DWORD,
						assembly::assembly_memory(machine::register_id::esp)
					}
				}
			));
			out_program.push_back(assembly::assembly_instruction(
				machine::operation::ADD,
				assembly::assembly_result{machine::register_id::esp},
				assembly::assembly_operand{4}
			));
		}
		out_program.push_back(assembly::assembly_instruction(
			machine::operation::HLT
		));
		out_program.emplace_back("__global_exit");
	}
	assembly::assembly_program_t Compiler::compile(const std::string& entry_function) {
		assembly::assembly_program_t program;
		this->precompile_functions();
		this->compile_entry(entry_function, program);
		for (const auto& func : m_built_in_functions | std::views::values) {
			program.insert(program.end(), func.implementation.begin(), func.implementation.end());
		}
		for (const auto& func_program : m_compiled_functions | std::views::values) {
			program.insert(program.end(), func_program.begin(), func_program.end());
		}
		return program;
	}
} // unqlang::compiler
