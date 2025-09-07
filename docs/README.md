# Misc Machine

I really now need to write stuff down.\
This is for now only a placeholder.\
I'll now be working on the 'compiler', that gets its own file.
For that go to [docs/COMPILER.md](COMPILER.md)


### COMMENTS
Now it works (mostly) perfectly, nasm style assembly, with comments, labels, everything
well im missing local labels, but I gotta look into them further

maybe I should add data commands too, like db, dw, dd, dq, and resb, resw, resd, resq, but for that to work,
I need to add segments, like .data, .bss, .text, and then handle them properly in the assembler
also the program would have to be in memory, currently it's separate, but if I want to do that, I need to merge them

maybe I should add a directive to set the origin, like org 0x100, so that the program starts at that address in memory
but then I need to handle that in the assembler too, and make sure the instruction pointer starts there
also interrupts, but that's for another time