/*
int main()
{
    r(25);
}

int r(int n)
{
    if(n <= 0) return 0;
    if(n == 1) return 1;
    return 2 * r(n - 1) + 3 * r(n - 2);
}
*/

push rdi ; call function 之前記得備份register的狀態
mov rdi, 16
call r
pop rdi

jmp exit

r: ; 照system V的規定，參數用rdi傳，return值放rax，parameter由caller刪
    push rbp
    mov rbp, rsp

    cmp rdi, 0
    jg L1
    mov rax, 0
    jmp leave_r

L1:
    cmp rdi, 1
    jne L2
    mov rax, 1
    jmp leave_r

L2:
    push rdi ; call function 之前記得備份register的狀態
    lea rdi, [rdi - 1]
    call r
    pop rdi
    lea rbx, [rax * 2]

    push rdi ; call function 之前記得備份register的狀態
    push rbx ; call function 之前記得備份register的狀態
    lea rdi, [rdi - 2]
    call r
    pop rbx
    pop rdi
    lea rcx, [rax + rax * 2]

    lea rax, [rbx + rcx]
    
leave_r:
    leave
    ret

exit: