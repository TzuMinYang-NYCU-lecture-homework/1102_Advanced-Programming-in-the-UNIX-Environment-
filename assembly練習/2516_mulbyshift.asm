/*
mulbyshift: multiply val1 by 26 and store the result in val2
======
      val1 @ 0x600000-600004
      val2 @ 0x600004-600008
======
*/
; 26 = 0b11010
mov eax, [0x600000]
mov ebx, eax
shl ebx, 4
mov ecx, eax
shl ecx, 3
shl eax, 1
add eax, ebx
add eax, ecx
mov [0x600004], eax