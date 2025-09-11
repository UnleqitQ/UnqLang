#include "functions.hpp"

namespace unqlang::analysis::functions {
	bool storage::declare_function(const std::string& name, const types::type_node& return_type,
		const std::vector<types::type_node>& parameter_types, bool is_defined) {
		if (functions.contains(name)) {
			auto& existing = functions.at(name);
			if (existing.is_defined && is_defined) {
				return false; // already defined
			}
			if (existing.parameter_types != parameter_types || existing.return_type != return_type) {
				return false; // signature mismatch
			}
			if (is_defined) {
				existing.is_defined = true; // update to defined
			}
			return true; // already declared with same signature
		}
		functions[name] = function_info(name, return_type, parameter_types);
		functions[name].is_defined = is_defined;
		return true;
	}
} // unqlang::analysis::functions
