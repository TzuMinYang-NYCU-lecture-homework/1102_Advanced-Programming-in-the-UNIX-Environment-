/*
loop15:
        str1 is a string contains 15 lowercase and uppercase alphbets.
        implement a loop to convert all alplabets to lowercase,
        and store the result in str2.
======
      str1 @ 0x600000-600010
      str2 @ 0x600010-600020
======
*/
mov edi, 0
L1:
cmp edi, 15
jge L2

mov al, [0x600000 + edi]
or al, 32
mov [0x600010 + edi], al

inc edi
jmp L1
L2: