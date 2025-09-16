#pragma once
#include <string>
#include <unordered_map>

namespace unqlang::analysis::complex_literals {
	struct storage {
		std::unordered_map<std::string, uint32_t> string_map;

		storage(): string_map() {
		}

		uint32_t add_string(const std::string& str) {
			if (const auto it = string_map.find(str); it != string_map.end()) {
				return it->second;
			}
			const uint32_t id = static_cast<uint32_t>(string_map.size());
			string_map[str] = id;
			return id;
		}
	};

	inline std::string string_label(uint32_t id) {
		return std::format("__str_{}__", id);
	}
} // unqlang::analysis::complex_literals
