#include "ast_helpers.hpp"

namespace unqlang {
	namespace type_helpers {
		uint16_t get_member_index(const ast_type_members& members, const std::string& name) {
			for (uint16_t i = 0; i < members.members.size(); ++i) {
				if (members.members[i].name == name) {
					return i;
				}
			}
			throw std::runtime_error("Member not found: " + name);
		}
	}
}
