/*
if ( eax >= 0 ) { var1 = 1 } else { var1 = -1 }
if ( ebx >= 0 ) { var2 = 1 } else { var2 = -1 }
if ( ecx >= 0 ) { var3 = 1 } else { var3 = -1 }
if ( edx >= 0 ) { var4 = 1 } else { var4 = -1 }
*/

cmp eax, 0
mov eax, 0x600000
jl L1
mov DWORD PTR [eax], 1
jmp L11
L1:
mov DWORD PTR [eax], -1
L11:

cmp ebx, 0
mov ebx, 0x600004
jl L2
mov DWORD PTR [ebx], 1
jmp L22
L2:
mov DWORD PTR [ebx], -1
L22:

cmp ecx, 0
mov ecx, 0x600008
jl L3
mov DWORD PTR [ecx], 1
jmp L33
L3:
mov DWORD PTR [ecx], -1
L33:

cmp edx, 0
mov edx, 0x60000c
jl L4
mov DWORD PTR [edx], 1
jmp L44
L4:
mov DWORD PTR [edx], -1
L44: