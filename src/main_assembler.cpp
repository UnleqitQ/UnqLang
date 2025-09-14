#include <chrono>

#include "assembly/assembly_parser.hpp"
#include "machine/computer.hpp"

// TODO: add port to input and output instructions
// TODO: add local labels (.L1, .L2, ... .Ln) that are scoped to the current function only

assembly::assembly_program_t parse_assembly(const std::string& source_code) {
	std::vector<assembly::assembly_token> assembly_tokens = assembly::run_lexer(source_code);

	// Clean up tokens: remove comments and join newlines
	assembly::remove_comments(assembly_tokens);
	std::vector<assembly::assembly_token> cleaned_tokens;
	assembly::join_newlines(assembly_tokens, cleaned_tokens);
	assembly_tokens = cleaned_tokens;

	std::vector<assembly::assembly_parse_component> assembly_components = assembly::run_component_parser(assembly_tokens);

	/*for (const auto& comp : assembly_components) {
		std::cout << comp << std::endl;
	}*/

	assembly::assembly_program_t assembly_program = assembly::run_parser(assembly_components);
	/*for (const auto& comp : assembly_program) {
		std::cout << comp << std::endl;
	}*/
	return assembly_program;
}

int main() {
	std::string source_code = R"(
jmp main
text_hello:
	db "Hello, World!", 0xA, 0

print_text:
	; Print a null-terminated string pointed to by EAX
	push eax
	push ecx
	mov ecx, eax          ; Copy string pointer to ECX
print_loop:
	mov al, byte ptr [ecx] ; Load byte at ECX into AL
	cmp al, 0              ; Check for null terminator
	jz print_done          ; If null, we're done
	; Output character in AL (using OUT instruction)
	out al
	inc ecx                ; Move to next character
	jmp print_loop
print_done:
	pop ecx
	pop eax
	ret

factorial:
	push ebp
	mov ebp, esp
	sub esp, 4                     ; Allocate space for local variable if needed
	mov eax, dword ptr [ebp + 8]   ; Get n (first argument)
	cmp eax, 1
	jle base_case                  ; If n <= 1, return 1
	dec eax                        ; n - 1
	push eax
	call factorial
	add esp, 4                     ; Clean up stack
	mov ebx, dword ptr [ebp + 8]   ; Get n again
	mul eax, ebx				           ; EAX = n * factorial(n - 1)
	jmp end_factorial
base_case:
	mov eax, 1                     ; Return 1
end_factorial:
	mov esp, ebp
	pop ebp
	ret

int_get_digits:
	; Get integer digits in EAX and store at address pointed by EDI and write number of digits to EAX
	push ebx
	push ecx
	push edx
	mov ecx, 0           ; Digit count
digit_loop:
	mov edx, eax         ; Copy EAX to EDX for division
	mod edx, 10          ; EDX = EAX % 10
	div eax, 10          ; EAX = EAX / 10
	push dl              ; Push digit onto stack
	inc ecx              ; Increment digit count
	cmp eax, 0
	jnz digit_loop       ; Repeat until EAX is 0
	mov eax, ecx         ; Move digit count to EAX (return value)
pop_digits:
	cmp ecx, 0
	jz digits_done       ; If no more digits, we're done
	pop dl               ; Get next digit
	mov byte ptr [edi], dl ; Store digit
	inc edi              ; Move to next memory location
	dec ecx              ; Decrement digit count
	jmp pop_digits
digits_done:
	pop edx
	pop ecx
	pop ebx
	ret

digits_to_string:
	; Convert digits at address pointed by ESI with size in EAX to null-terminated string at address pointed by EDI
	push ebx
	push ecx
	mov ecx, eax         ; Get size
string_loop:
	cmp ecx, 0
	jz string_done       ; If size is 0, we're done
	mov bl, byte ptr [esi] ; Load digit
	add bl, '0'         ; Convert to ASCII
	mov byte ptr [edi], bl ; Store character
	inc esi              ; Move to next BCD digit
	inc edi              ; Move to next string position
	dec ecx              ; Decrement size
	jmp string_loop
string_done:
	mov byte ptr [edi], 0 ; Null-terminate the string
	pop ecx
	pop ebx
	ret

main:
	mov eax, text_hello
	call print_text

	mov eax, 5           ; Calculate factorial of 5
	push eax
	call factorial
	; Result is in EAX
	mov ebx, eax         ; Save factorial result in EBX
	mov edi, 0x2000      ; Buffer for digits
	call int_get_digits
	; Number of digits is in EAX
	mov esi, 0x2000      ; Digits are stored starting at 0x2000
	mov edi, 0x3000      ; Buffer for string
	call digits_to_string
	; String is now at 0x3000
	mov eax, 0x3000
	call print_text
	add esp, 4           ; Clean up stack
	; Result is in EAX

	; Exit program
	mov eax, 0
	end
)";
	assembly::assembly_program_t assembly_program = parse_assembly(source_code);
	// Assemble and run the program
	// Load program at 1/3rd of RAM size to leave space for stack and heap
	const uint32_t start_address = machine::ram::SIZE / 3;
	machine::program_t program = assembly::assemble(assembly_program, true, start_address);
	machine::computer computer;
	computer.load_program(program, start_address);
	computer.set_verbose(false);
	computer.run();
	return 0;
}
