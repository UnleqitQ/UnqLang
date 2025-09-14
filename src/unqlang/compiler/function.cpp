#include "function.hpp"

namespace unqlang::compiler {
	std::shared_ptr<assembly_function_signature> function_signature::build_assembly_signature(
		const analysis::types::type_system& type_system
	) const {
		auto asm_sig = std::make_shared<assembly_function_signature>();
		asm_sig->name = name;
		asm_sig->return_type = return_type;
		asm_sig->is_variadic = is_variadic;
		asm_sig->parameters.reserve(parameters.size());
		uint32_t current_offset = 8; // return address + old base pointer
		for (const auto& param : parameters) {
			uint32_t param_size = type_system.get_type_size(param.type);
			// no alignment handling (yet)
			assembly_parameter_info asm_param(
				param.name,
				param.type,
				param.index,
				current_offset
			);
			asm_sig->parameters.push_back(asm_param);
			current_offset += param_size;
			if (param.name) asm_sig->name_index_map.emplace(*param.name, param.index);
		}
		uint32_t total_param_size = current_offset - 8;
		asm_sig->parameter_stack_size = total_param_size;
		uint32_t return_type_size = type_system.get_type_size(return_type);
		asm_sig->return_value_size = return_type_size;
		asm_sig->stack_size = std::max(total_param_size, return_type_size);
		return asm_sig;
	}
} // unqlang::compiler
