/*
dispbin:
        given a number in AX, store the corresponding bit string in str1.
        for example, if AX = 0x1234, the result should be:
        str1 = 0001001000111000
======
      str1 @ 0x600000-600014
*/
/*
str = 0x1234

for i 0~3
    ch = str[3 - i]
    for j 0~3
        bin[0x600003 + i * 4 - j] = x%2
        x /= 2
*/

mov ebx, eax ; ebx = 原本字串
mov edi, 0
mov ebp, 2 ; ebp = 除數
L1:
    cmp  edi, 4
    jge L2

    mov eax, ebx 
    lea ecx, [edi * 4 - 12]
    neg ecx      ; ecx = 要shift的位數 = 12 - edi * 4
    shr eax, ecx 
    and eax, 0xf ; eax = 本次要處理的字元

    mov esi, 0
L3:
    cmp esi, 4
    jge L4

    cdq
    div ebp    ; eax /= 2  edx = eax % 2

    lea ecx, [edi * 4 + 0x600003]
    sub ecx, esi  ; ecx = 本次要放的mem位置 = 0x600004 + edi * 4 - esi
    lea edx, [edx + 48] ; 要轉成ascii的數字
    mov [ecx], dl ; 注意一次放1byte就好，放太大會蓋到後面的

    inc esi
    jmp L3
L4:
    inc edi
    jmp L1
L2:
