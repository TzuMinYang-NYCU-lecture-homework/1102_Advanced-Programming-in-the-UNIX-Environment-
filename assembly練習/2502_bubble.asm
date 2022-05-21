/*
bubble: bubble sort for 10 integers
======
      a[0] @ 0x600000-600004
      a[1] @ 0x600004-600008
      a[2] @ 0x600008-60000c
      a[3] @ 0x60000c-600010
      a[4] @ 0x600010-600014
      a[5] @ 0x600014-600018
      a[6] @ 0x600018-60001c
      a[7] @ 0x60001c-600020
      a[8] @ 0x600020-600024
      a[9] @ 0x600024-600028
======

*/

/*
for(int i = 0; i < 10; i++)
    for(int j = 0; j < 10 - 1 - i; j++)
        if(a[j] < a[j + 1])
            swap(a[j], a[j+1])
*/

mov edi, 0
L1:
    cmp  edi, 10
    jge L2

    mov esi, 0
    lea ebp, [edi - 9]  
    neg ebp             ; ebp = 9 - i
L3:
    cmp esi, ebp
    jge L4

    lea eax, [esi * 4 + 0x600000]
    lea ebx, [eax + 4]
    mov ecx, [eax]  ; !!!本來用r8和r9，但是有問題，不知道原因
    mov edx, [ebx]  

    cmp ecx, edx
    jl L5
    mov [eax], edx
    mov [ebx], ecx
L5:

    inc esi
    jmp L3
L4:
    inc edi
    jmp L1
L2:
