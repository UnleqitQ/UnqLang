#include <iostream>

#include "assembly/assembly_parser.hpp"
#include "parser.hpp"
#include "machine/computer.hpp"

// F*CK, X86 saves the result in the first operand, I thought there were result, op1 [, op2]
// leaving this comment, for future me to remember this bullshit
// like I did more work, and now even more work to fix this, I hate myself
// But else it works perfectly, nasm style assembly, with comments, labels, everything
// well im missing local labels, but I gotta look into them further
// hey writing this is kinda fun XD, tomorrow I'll be like "why the hell did I write so much?", oh well

// maybe I should add data commands too, like db, dw, dd, dq, and resb, resw, resd, resq, but for that to work,
// I need to add segments, like .data, .bss, .text, and then handle them properly in the assembler
// also the program would have to be in memory, currently it's separate, but if I want to do that, I need to merge them

// maybe I should add a directive to set the origin, like org 0x100, so that the program starts at that address in memory
// but then I need to handle that in the assembler too, and make sure the instruction pointer starts there
// also interrupts, but that's for another time

// ok now I really gotta stop writing comments, this is getting out of hand
// and I need to sleep, it's past 1am

int main() {
	// Test the assembly tokenizer
	std::string assembly_code = R"(
; recursive factorial
start:
	mov eax, 5         ; number to compute factorial of
	call fact
	out eax
	hlt
fact:
	cmp eax, 1
	jle fact_basecase
	; make space on stack
	sub esp, es
	push eax
	dec eax
	call fact
	pop ebx
	mul eax, eax, ebx
	ret
fact_basecase:
	mov eax, 1
	ret
)";
	auto tokens = assembly::run_lexer(assembly_code);
	std::cout << "Tokens:" << std::endl;
	for (const auto& token : tokens) {
		std::cout << token << std::endl;
	}
	assembly::remove_comments(tokens);
	std::vector<assembly::assembly_token> cleaned_tokens;
	assembly::join_newlines(tokens, cleaned_tokens);
	std::cout << "\nTokens after removing comments and joining newlines:" << std::endl;
	for (const auto& token : cleaned_tokens) {
		std::cout << token << std::endl;
	}
	auto components = assembly::run_component_parser(cleaned_tokens);
	std::cout << "\nParse Components:" << std::endl;
	for (const auto& comp : components) {
		std::cout << comp.to_string() << std::endl;
	}
	assembly::assembly_program_t assembly_program = assembly::run_parser(components);
	std::cout << "\nParsed Assembly Components:" << std::endl;
	for (const auto& p : assembly_program) {
		std::cout << p << std::endl;
	}

	machine::program_t program = assembly::assemble(assembly_program);
	machine::computer computer;
	computer.load_program(program);

	std::cout << "\nRunning program..." << std::endl;
	std::cout << std::endl << std::string(40, '=') << std::endl << std::endl;
	computer.set_verbose(true);
	computer.run(1000);
	return 0;
}
