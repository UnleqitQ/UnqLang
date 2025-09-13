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
		regmask used_regs
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
			compile_primitive_expression(src, context, program, current_scope, target_reg, used_regs | dest_regs);
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
			compile_primitive_expression(src, context, program, current_scope, target_reg, used_regs | dest_regs);
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
			auto addr = compile_reference(src, context, temp_program, current_scope, used_regs | dest_regs);
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
		regmask used_regs
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
					auto inner_ref = compile_reference(*unary.operand, context, program, current_scope, used_regs);
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
				used_regs.set(addr_reg, true);
				compile_primitive_expression(*unary.operand, context, program, current_scope, addr_reg, used_regs);
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
							auto left_ref = compile_reference(*binary.left, context, program, current_scope, used_regs);
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
						used_regs.set(index_reg, true);
						// compile right side expression into index_reg
						compile_primitive_expression(*binary.right, context, program, current_scope, index_reg, used_regs);
						// store program in temporary program to not mess up the register usage
						// (since we might need to save/restore registers below)
						assembly::assembly_program_t temp_program;
						auto val_mem = compile_reference(*binary.left, context, temp_program, current_scope, used_regs);
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
						auto left_ref = compile_reference(*binary.left, context, program, current_scope, used_regs);
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
							used_regs
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
					return compile_reference(*member_access.object, context, program, current_scope, used_regs);
				}
				// get the struct type
				auto struct_type = std::get<analysis::types::struct_type>(object_type.value);
				// find the member
				auto member_info =
					context.global_context->type_system->get_struct_member_info(struct_type, member_access.member);
				// get reference to base object
				auto base_ref = compile_reference(*member_access.object, context, program, current_scope, used_regs);
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

	void compile_boolean_binary_expression(const analysis::expressions::binary_expression& binary,
		const scoped_compilation_context& context, assembly::assembly_program_t& program, assembly_scope& current_scope,
		machine::register_t target_reg, regmask used_regs, analysis::types::type_node left_type,
		analysis::types::type_node right_type) {
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
			compile_primitive_expression(*binary.left, context, program, current_scope, left_reg_t, used_regs);
			used_regs.set(target_reg.id, true);
			compile_primitive_expression(*binary.right, context, program, current_scope, right_reg_t, used_regs);

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
		compile_primitive_expression(*binary.left, context, program, current_scope, bool_reg, used_regs);
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
		compile_primitive_expression(*binary.right, context, temp_program, current_scope, bool_reg, used_regs);
		uint32_t size = assembly::program_size(temp_program);
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
		const analysis::types::type_node& dest_type
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
						auto ref = compile_reference(*unary.operand, context, temp_program, current_scope, used_regs);
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
						compile_primitive_expression(*unary.operand, context, program, current_scope, target_reg, used_regs);
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
				}
			}
		}
	}

	void compile_primitive_expression(
		const analysis::expressions::expression_node& expr,
		const scoped_compilation_context& context,
		assembly::assembly_program_t& program,
		assembly_scope& current_scope,
		machine::register_t target_reg,
		regmask used_regs
	) {
		auto dest_type = context.global_context->type_system->resolved_type(
			expr.get_type(
				*context.variable_storage,
				*context.global_context->function_storage,
				*context.global_context->type_system
			)
		);
		if (dest_type.kind == analysis::types::type_node::kind_t::POINTER) {
			auto pointer_type = std::get<analysis::types::pointer_type>(dest_type.value);
			auto pointee_type = context.global_context->type_system->resolved_type(*pointer_type.pointee_type);
			compile_pointer_expression(expr, context, program, current_scope, target_reg, used_regs, pointee_type);
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
						compile_pointer_expression(
							*unary.operand, context, program, current_scope, target_reg.id, used_regs, pointee_type
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
						compile_primitive_expression(*unary.operand, context, program, current_scope, target_reg, used_regs);
						// negate the value in target_reg
						program.push_back(assembly::assembly_instruction(
							machine::operation::NEG,
							assembly::assembly_result(target_reg)
						));
						return;
					}
					case analysis::expressions::unary_expression::operator_t::NOT: {
						compile_primitive_expression(*unary.operand, context, program, current_scope, target_reg, used_regs);
						// perform bitwise NOT on the value in target_reg
						program.push_back(assembly::assembly_instruction(
							machine::operation::NOT,
							assembly::assembly_result(target_reg)
						));
						return;
					}
					case analysis::expressions::unary_expression::operator_t::LNOT: {
						compile_primitive_expression(*unary.operand, context, program, current_scope, target_reg.id, used_regs);
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
						compile_primitive_expression(*unary.operand, context, program, current_scope, target_reg, used_regs);
						return;
					}
					case analysis::expressions::unary_expression::operator_t::SIZEOF:
						throw std::runtime_error("Sizeof operator not implemented yet");
					case analysis::expressions::unary_expression::operator_t::PRE_DEC:
					case analysis::expressions::unary_expression::operator_t::PRE_INC: {
						// getting the reference to the expression already modifies it for us
						assembly::assembly_program_t temp_program;
						auto ref = compile_reference(unary, context, temp_program, current_scope, used_regs);
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
						auto ref = compile_reference(*unary.operand, context, temp_program, current_scope, used_regs);
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
					compile_pointer_expression(
						left, context, program, current_scope, target_reg.id, used_regs, left_type
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
					used_regs.set(target_reg.id, true);
					if (used_regs.get(right_reg_id)) {
						program.push_back(assembly::assembly_instruction(
							machine::operation::PUSH,
							assembly::assembly_operand{right_reg_id}
						));
					}
					compile_pointer_expression(
						right, context, program, current_scope, right_reg_id, used_regs, right_type
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
						left_type,
						right_type
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
					compile_pointer_expression(left, context, program, current_scope, target_reg, used_regs, left_type);
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
					used_regs.set(target_reg.id, true);
					bool index_is_used = used_regs.get(index_reg_id);
					if (index_is_used) {
						program.push_back(assembly::assembly_instruction(
							machine::operation::PUSH,
							assembly::assembly_operand{index_reg_id}
						));
					}
					compile_primitive_expression(
						right, context, program, current_scope, {index_reg_id, machine::register_access::dword}, used_regs
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
				compile_primitive_expression(left, context, program, current_scope, target, used_regs);
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
					used_regs
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
						auto ref = compile_reference(left, context, temp_program, current_scope, used_regs);
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
							used_regs
						);
						// load the assigned value into target_reg
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
			case analysis::expressions::expression_node::kind_t::CALL:
				throw std::runtime_error("Function calls not implemented yet");
			case analysis::expressions::expression_node::kind_t::MEMBER:
				throw std::runtime_error("Member access not implemented yet");
			case analysis::expressions::expression_node::kind_t::TERNARY:
				throw std::runtime_error("Ternary operator not implemented yet");
			default:
				throw std::runtime_error("Unknown expression type");
		};
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
} // unqlang::compiler
