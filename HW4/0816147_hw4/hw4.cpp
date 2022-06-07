#include <assert.h>                                                                
#include <stdio.h>                                                                 
#include <stdlib.h>                                                                
#include <unistd.h>                                                                
#include <sys/types.h>         
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <string.h>
#include <sys/user.h>
#include <elf.h>
#include <capstone/capstone.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
// 其實C++的部份只有用到vector
#include <vector>
#include <algorithm>

#define MAXLINE 256
#define MAXBREAKPOINT 256
#define WORDSIZE 8

using namespace std;
                                         
void errquit(const char *msg) {
    perror(msg);
    exit(-1);                                                                                                                                                     
} 

struct breakpoint_info
{
    char machine_code[MAXLINE], instruction[MAXLINE];
    unsigned long long address;
    int ori_instr; // 紀錄原指令的第一個byte
};

vector<breakpoint_info> breakpoint;
int states = 1; // 0:any 1:not loaded 2:loaded 3:running
pid_t child = -1;
int status;
struct user_regs_struct regs;
unsigned long long entrypoint, endpoint;
char program[MAXLINE] = "";
char *endptr; // 沒用, 給strtoull用的, 懶的每次都宣告一次

// Either Elf64_Ehdr or Elf32_Ehdr depending on architecture.
// 自己根據硬體架構接成Elf64_{type}或Elf32_{type}
#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif


void sdb_break(char *char_addr) // [running]
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }

    unsigned long long addr = strtoull(char_addr, &endptr, 16); // 不會有不是不合法的字元當作addr的情況, 所以就直接轉
    if(addr < entrypoint || addr > endpoint)
    {
        printf("** the address is out of the range of the text segment\n");
        return;
    }

    for(size_t i = 0; i < breakpoint.size(); ++i)
    {
        if(breakpoint[i].address == addr)
        {
            printf("** the breakpoint is already exists. (breakpoint %ld)\n", i);
            return;
        }        
    }

    // 助教說不會有breakpoint設在entrypoint的情況
    // intel instruction 最長15bytes
    char all_bytes[MAXLINE] = "";
    unsigned long long word;
    int ori_instr;

    errno = 0; // 用PEEK*的函式前要先清除errno
    word = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
    memcpy(&all_bytes, &word, WORDSIZE); //不能用 strncat(all_bytes, (char*)&word, WORDSIZE); 因為00會被當\0被忽略
    ori_instr = word & 0xff;
    word = (word & 0xffffffffffffff00) | 0xcc;
    ptrace(PTRACE_POKETEXT, child, addr, word); // 注意最後一個參數不用先取&, 前面給不給(void*)都可以

    for(int i = 1; i < 15 / WORDSIZE + 1; ++i)
    {
        errno = 0; // 用PEEK*的函式前要先清除errno
        word = ptrace(PTRACE_PEEKTEXT, child, addr + i * WORDSIZE, 0);
        memcpy(&all_bytes[i * WORDSIZE], &word, WORDSIZE); //不能用 strncat(all_bytes, (char*)&word, WORDSIZE); 因為00會被當\0被忽略
    }

    csh handle;
	cs_insn *insn;
	size_t count;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errquit("cs_open");

    // disasemble
	if ((count = cs_disasm(handle, (uint8_t*)all_bytes, (15 / WORDSIZE + 1) * WORDSIZE, addr, 0, &insn)) > 0) 
    {
        breakpoint_info bp;
        bp.address = insn[0].address;

        for(int i = 0; i < insn[0].size; ++i)
            snprintf(&bp.machine_code[i * 3], 4, " %02x", insn[0].bytes[i]); // snprintf連\0也會寫進去, 所以size要給4不是給3

        snprintf(bp.instruction, MAXLINE, "%-10s\t%s", insn[0].mnemonic, insn[0].op_str);
        bp.ori_instr = ori_instr;
        breakpoint.emplace_back(bp);
		cs_free(insn, count);
	} 
    else printf("** ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
}

void resume_all_breakpoint() // start或run時才會被call到
{
    // 重新在每個breakpoint上設定0xcc
    unsigned long long word;

    for(size_t i = 0; i < breakpoint.size(); ++i)
    {
        errno = 0; // 用PEEK*的函式前要先清除errno
        word = ptrace(PTRACE_PEEKTEXT, child, breakpoint[i].address, 0);
        word = (word & 0xffffffffffffff00) | 0xcc;
        ptrace(PTRACE_POKETEXT, child, breakpoint[i].address, word); // 注意最後一個參數不用先取&, 前面給不給(void*)都可以        
    }
}

void detect_breakpoint(int which) // which = 0: si, else: cont
{   
    // 取得rip
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);

    // 檢查目前是不是在breakpoint

    // 1.用si跑到breakpoint前, 還沒執行到breakpoint的0xcc, 就要先判斷碰到breakpoint了
    if(which == 0)
    {
        for(size_t i = 0; i < breakpoint.size(); ++i)
        {
            if(breakpoint[i].address == regs.rip)
            {
                printf("** breakpoint @      %llx: %-32s %s\n", breakpoint[i].address, breakpoint[i].machine_code, breakpoint[i].instruction);
                return;
            }
        }
    }

    // 2.用cont執行到breakpoint的0xcc而停下來
    else
    {
        regs.rip -= 1; // 因為等等要判斷和更新進去的rip都是-1之後的, 所以先-1
        for(size_t i = 0; i < breakpoint.size(); ++i)
        {
            if(breakpoint[i].address == regs.rip)
            {
                printf("** breakpoint @      %llx: %-32s %s\n", breakpoint[i].address, breakpoint[i].machine_code, breakpoint[i].instruction);
                // 還原rip到還沒執行0xcc之前, 也就是讓rip-1
                ptrace(PTRACE_SETREGS, child, 0, &regs);
                return;
            }
        }
    }
}

int leave_breakpoint()
{
    // 取得rip
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);

    // 看接下來要run的指令是不是breakpoint, 要用找的, 因為可能用set rip的方式改變執行順序
    int cur_breakpoint = -1;
    for(size_t i = 0; i < breakpoint.size(); ++i) 
    {
        if(regs.rip == breakpoint[i].address)
        {
            cur_breakpoint = i;
            break;
        }        
    }

    if(cur_breakpoint == -1) return 0; // 接下來要run的不是breakpoint


    // 先還原指令內容, 畢竟breakpoint這行還是要執行
    unsigned long long word;

    errno = 0; // 用PEEK*的函式前要先清除errno
    word = ptrace(PTRACE_PEEKTEXT, child, breakpoint[cur_breakpoint].address, 0);
    word = (word & 0xffffffffffffff00) | breakpoint[cur_breakpoint].ori_instr;
    ptrace(PTRACE_POKETEXT, child, breakpoint[cur_breakpoint].address, word); // 注意最後一個參數不用先取&, 前面給不給(void*)都可以

    // run SINGLESTEP
    ptrace(PTRACE_SINGLESTEP, child, 0, 0);               
    waitpid(child, &status, 0);

    // 把0xcc設回去, 因為要重複使用breakpoint
    word = (word & 0xffffffffffffff00) | 0xcc;
    ptrace(PTRACE_POKETEXT, child, breakpoint[cur_breakpoint].address, word); // 注意最後一個參數不用先取&, 前面給不給(void*)都可以

    return 1;
}

void sdb_cont() // [running]
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }

    leave_breakpoint();
    
    ptrace(PTRACE_CONT, child, 0, 0);               
    waitpid(child, &status, 0);
    if(WIFEXITED(status))
    {
        printf("** child process %d terminiated normally (code %d)\n", child, status);
        states = 2;
    }
    else if(WIFSTOPPED(status)) detect_breakpoint(1);
    else printf("** child process error status\n");
}

void sdb_delete(char *char_breakpoint_id) // [running]
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }
    
    int breakpoint_id = strtol(char_breakpoint_id, &endptr, 10);
    if((size_t)breakpoint_id >= breakpoint.size())
    {
        printf("** breakpoint %d does not exist\n", breakpoint_id);
        return;
    }

    // 還原指令內容
    unsigned long long word;

    errno = 0; // 用PEEK*的函式前要先清除errno
    word = ptrace(PTRACE_PEEKTEXT, child, breakpoint[breakpoint_id].address, 0);
    word = (word & 0xffffffffffffff00) | breakpoint[breakpoint_id].ori_instr;
    ptrace(PTRACE_POKETEXT, child, breakpoint[breakpoint_id].address, word); // 注意最後一個參數不用先取&, 前面給不給(void*)都可以

    // 從vector中刪除此breakpoint
    breakpoint.erase(breakpoint.begin() + breakpoint_id);

    printf("** breakpoint %d deleted.\n", breakpoint_id);
}

void sdb_disasm(char *char_addr) // [running]
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }

    unsigned long long addr = strtoull(char_addr, &endptr, 16);
    if(addr < entrypoint || addr > endpoint)
    {
        printf("** the address is out of the range of the text segment\n");
        return;
    }

    csh handle;
	cs_insn *insn;
	size_t count;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errquit("cs_open");

    // intel 一個instruction最多有15bytes, 而助教要求最多10個intructions就好
    // 助教說disasm後面接的位址只會是指令的第一個位址, 所以不用處理其他情況
    int bytes_len = 15 * 10 / WORDSIZE + 3; // +3是多撈一些資料避免有問題
    char all_bytes[MAXLINE] = "";
    unsigned long long word;

    for(int i = 0; i < bytes_len; ++i) 
    {
        errno = 0; // 用PEEK*的函式前要先清除errno
        word = ptrace(PTRACE_PEEKTEXT, child, addr + i * WORDSIZE, 0);
        memcpy(&all_bytes[i * WORDSIZE], &word, WORDSIZE); //不能用 strncat(all_bytes, (char*)&word, WORDSIZE); 因為00會被當\0被忽略
    }

    // 碰到breakpoint要把all_bytes的內容還原成原本的instruction內容
    for(int i = 0; i < bytes_len * WORDSIZE; ++i)
        if(all_bytes[i] == (char)0xcc)
            for(size_t j = 0; j < breakpoint.size(); ++j)
                if(addr + i == breakpoint[j].address) 
                    all_bytes[i] = breakpoint[j].ori_instr;

    // disasemble
	if ((count = cs_disasm(handle, (uint8_t*)all_bytes, bytes_len * WORDSIZE, addr, 0, &insn)) > 0) 
    {
		for (size_t i = 0; i < count && i < 10; ++i) // 助教說輸出10個instructions就好
        {
            if(insn[i].address > endpoint) // 超出範圍之後的都不用輸出了
            {
                printf("** the address is out of the range of the text segment\n");
                break;
            }
            else
            {
                printf("      %lx:", insn[i].address);
                char machine_code[MAXLINE] = "";
                for(int j = 0; j < insn[i].size; ++j)
                    snprintf(&machine_code[j * 3], 4, " %02x", insn[i].bytes[j]); // snprintf連\0也會寫進去, 所以size要給4不是給3
                printf("%-32s\t%-10s\t%s\n", machine_code, insn[i].mnemonic, insn[i].op_str);
            }
        }
		cs_free(insn, count);
	} 
    else printf("** ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
}

void sdb_dump(char *char_addr) // [running]
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }

    unsigned long long int_addr = strtoull(char_addr, &endptr, 16), word;
    char char_byte;
    for(int i = 0; i < 5; ++i)
    {
        printf("      0x%llx: ", int_addr);

        char single_line[MAXLINE] = "";
        for(int j = 0; j < 16 / WORDSIZE; ++j)
        {
            errno = 0; // 用PEEK*的函式前要先清除errno
            word = ptrace(PTRACE_PEEKTEXT, child, int_addr + j * WORDSIZE, 0);

            // 因為一次會取一個word(8 bytes)出來, 所以要每個byte分開處理
            for(int k = 0; k < WORDSIZE; ++k)
            {
                printf("%02llx ", word & 0xff); // word & 0xff = 這次要處理的byte, 因為是little endian
                if(isprint(word & 0xff)) char_byte = (char)(word & 0xff);
                else char_byte = '.';
                strncat(single_line, &char_byte, 1);
                word = word >> 8; // 1 byte = 8 bits, 把接下來要處理的byte移到最後面
            }
            
        }
        printf("|%s|\n", single_line);
        int_addr += 0x10;
    }
}

void sdb_exit() // [any]
{
    exit(0);
}

void sdb_get(char *char_reg) // [running]
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }    
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    if(strcmp(char_reg, "rax") == 0)        printf("rax = %llu (0x%llx)\n", regs.rax, regs.rax);
    else if(strcmp(char_reg, "rbx") == 0)   printf("rbx = %llu (0x%llx)\n", regs.rbx, regs.rbx);
    else if(strcmp(char_reg, "rcx") == 0)   printf("rcx = %llu (0x%llx)\n", regs.rcx, regs.rcx);
    else if(strcmp(char_reg, "rdx") == 0)   printf("rdx = %llu (0x%llx)\n", regs.rdx, regs.rdx);
    else if(strcmp(char_reg, "r8") == 0)    printf("r8 = %llu (0x%llx)\n", regs.r8, regs.r8);
    else if(strcmp(char_reg, "r9") == 0)    printf("r9 = %llu (0x%llx)\n", regs.r9, regs.r9);
    else if(strcmp(char_reg, "r10") == 0)   printf("r10 = %llu (0x%llx)\n", regs.r10, regs.r10);
    else if(strcmp(char_reg, "r11") == 0)   printf("r11 = %llu (0x%llx)\n", regs.r11, regs.r11);
    else if(strcmp(char_reg, "r12") == 0)   printf("r12 = %llu (0x%llx)\n", regs.r12, regs.r12);
    else if(strcmp(char_reg, "r13") == 0)   printf("r13 = %llu (0x%llx)\n", regs.r13, regs.r13);
    else if(strcmp(char_reg, "r14") == 0)   printf("r14 = %llu (0x%llx)\n", regs.r14, regs.r14);
    else if(strcmp(char_reg, "r15") == 0)   printf("r15 = %llu (0x%llx)\n", regs.r15, regs.r15);
    else if(strcmp(char_reg, "rdi") == 0)   printf("rdi = %llu (0x%llx)\n", regs.rdi, regs.rdi);
    else if(strcmp(char_reg, "rsi") == 0)   printf("rsi = %llu (0x%llx)\n", regs.rsi, regs.rsi);
    else if(strcmp(char_reg, "rbp") == 0)   printf("rbp = %llu (0x%llx)\n", regs.rbp, regs.rbp);
    else if(strcmp(char_reg, "rsp") == 0)   printf("rsp = %llu (0x%llx)\n", regs.rsp, regs.rsp);
    else if(strcmp(char_reg, "rip") == 0)   printf("rip = %llu (0x%llx)\n", regs.rip, regs.rip);
    else if(strcmp(char_reg, "flags") == 0) printf("flags = %llu (0x%llx)\n", regs.eflags, regs.eflags);
}

void sdb_getregs() // [running]
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    printf("RAX %-14llx RBX %-14llx RCX %-14llx RDX %-14llx\nR8  %-14llx R9  %-14llx R10 %-14llx R11 %-14llx\nR12 %-14llx R13 %-14llx R14 %-14llx R15 %-14llx\nRDI %-14llx RSI %-14llx RBP %-14llx RSP %-14llx\nRIP %-14llx FLAGS %016llx\n",
           regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.rdi, regs.rsi, regs.rbp, regs.rsp, regs.rip, regs.eflags);
}

void sdb_help() // [any]
{
    printf("- break {instruction-address}: add a break point\n- cont: continue execution\n- delete {break-point-id}: remove a break point\n- disasm addr: disassemble instructions in a file or a memory region\n- dump addr: dump memory content\n- exit: terminate the debugger\n- get reg: get a single value from a register\n- getregs: show registers\n- help: show this message\n- list: list break points\n- load {path/to/a/program}: load a program\n- run: run the program\n- vmmap: show memory layout\n- set reg val: get a single value to a register\n- si: step into instruction\n- start: start the program and stop at the first instruction\n");
}

void sdb_list() // [any]
{
    for(size_t i = 0; i < breakpoint.size(); ++i)
        printf("  %ld: %llx\n", i, breakpoint[i].address);
}

void sdb_load() // [not loaded]
{
    if(states != 1)
    {
        printf("** state must be NOT LOADED\n");
        return;
    }

    FILE* elf_file = fopen(program, "rb"); // 記得要用binary開
    if(elf_file) 
    {
        // 讀出elf header
        ElfW(Ehdr) elf_header;
        fread(&elf_header, sizeof(elf_header), 1, elf_file);
        entrypoint = elf_header.e_entry;

        // section中有一個叫做shstrtab, 紀錄了每個section的名字, 用\0分隔(!!! 開頭好像是\0), 所以現在要先去取得section table中紀錄shstrtab的entry
        ElfW(Shdr) section_header; // section table中的一個entry
        fseek(elf_file, elf_header.e_shoff + elf_header.e_shstrndx * sizeof(section_header), SEEK_SET); // e_shoff是section header的offset, e_shstrndx是shstrtab是第幾個entry
        fread(&section_header, 1, sizeof(section_header), elf_file);

        // 讀出shstrtab的內容
        char *shstrtab_section = (char*)malloc(section_header.sh_size); // sh_size是此section的大小
        fseek(elf_file, section_header.sh_offset, SEEK_SET); // sh_offset是此section在ELF的位置
        fread(shstrtab_section, 1, section_header.sh_size, elf_file); 

        // 讀每個section, 找text section
        for (int i = 0; i < elf_header.e_shnum; i++) // e_shnum是section的數量
        {
            const char* section_name = "";

            // 讀section header中第i個entry的資料
            fseek(elf_file, elf_header.e_shoff + i * sizeof(section_header), SEEK_SET);
            fread(&section_header, 1, sizeof(section_header), elf_file);

            if (section_header.sh_name) // sh_name是此section的name在shstrtab的offset !!!好像不會是0, 所以才先判斷不是0
            {
                // 取得section name
                section_name = shstrtab_section + section_header.sh_name;
                if(strcmp(section_name, ".text") == 0)
                {
                    endpoint = elf_header.e_entry + section_header.sh_size - 1;
                    break;
                }
            }
        }

        // finally close the file
        fclose(elf_file);

        states = 2;
        printf("** program '%s' loaded. entry point 0x%llx\n", program, entrypoint);
    }
    else
    {
        printf("** can't open this file\n");
        exit(0);
    }
}

void sdb_start() // [loaded]
{
    if(states != 2)
    {
        printf("** program %s is already running\n", program);
        return;
    }

    if((child = fork()) < 0) errquit("fork");
    if(child == 0) 
    {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
        execlp(program, program, NULL); // 助教說program不會有附參數的情況, 所以就不處理了
        errquit("execlp");
    }
    else
    {
        if(waitpid(child, &status, 0) < 0) errquit("waitpid");
        assert(WIFSTOPPED(status));
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL); // tracer exit時送SIGKILL給tracee

        resume_all_breakpoint(); // 處理跑多次program的情況
        printf("** pid %d\n", child);
        states = 3;
    }
}

void sdb_run() // [loaded and running]
{
    if(states == 3)
    {
        printf("** program %s is already running\n", program);
        sdb_cont();
    }
    else if(states == 2)
    {
        sdb_start(); // 已檢查過states, 所以不用擔心會有兩個states錯誤的提示訊息出現
        sdb_cont();        
    }
    else
    {
        printf("** state must be LOADED or RUNNING\n");
    }
}

void sdb_vmmap()
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }

    // 讀/proc/{child}/maps來獲得需要的資訊
    char map_file_path[MAXLINE];
    snprintf(map_file_path, MAXLINE, "/proc/%d/maps", child);
    FILE* map_file = fopen(map_file_path, "r");

    char single_line[MAXLINE] = "";
    while(fgets(single_line, MAXLINE, map_file) != NULL)
    {
        char *vm_start = strtok(single_line, "-");
        char *vm_end = strtok(NULL, " ");
        char *vm_flags = strtok(NULL, " ");
        char *vm_pgoff = strtok(NULL, " ");
        strtok(NULL, " ");
        strtok(NULL, " ");
        char *filename;
        if((filename = strtok(NULL, " ")) == NULL) continue;  // 處理沒檔名的那個case, 不用輸出東西, 跳過就好; 最後一個不用有分隔符也可以取出來(filename後面不用有空白, 也能取出來, 但因為filename是要被切的最後一個才行)

        strncpy(vm_flags + strlen(vm_flags) - 1, "\0", 1); // 去除最後的p
        printf("%016llx-%016llx %s %-7llx %s", strtoull(vm_start, &endptr, 16), strtoull(vm_end, &endptr, 16), vm_flags, strtoull(vm_pgoff, &endptr, 16), filename);
    }
}

void sdb_set(char *char_reg, char *char_val)
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    
    if(strcmp(char_reg, "rax") == 0)        regs.rax = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "rbx") == 0)   regs.rbx = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "rcx") == 0)   regs.rcx = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "rdx") == 0)   regs.rdx = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "r8") == 0)    regs.r8 = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "r9") == 0)    regs.r9 = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "r10") == 0)   regs.r10 = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "r11") == 0)   regs.r11 = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "r12") == 0)   regs.r12 = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "r13") == 0)   regs.r13 = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "r14") == 0)   regs.r14 = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "r15") == 0)   regs.r15 = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "rdi") == 0)   regs.rdi = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "rsi") == 0)   regs.rsi = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "rbp") == 0)   regs.rbp = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "rsp") == 0)   regs.rsp = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "rip") == 0)   regs.rip = strtoull(char_val, &endptr, 16);
    else if(strcmp(char_reg, "flags") == 0) regs.eflags = strtoull(char_val, &endptr, 16);
    ptrace(PTRACE_SETREGS, child, 0, &regs);
}

void sdb_si()
{
    if(states != 3)
    {
        printf("** state must be RUNNING\n");
        return;
    }

    if(leave_breakpoint() == 0) // 若leave_breakpoint裡面有跑過一次SINGLESTEP, 這邊就不用跑了; 反之則這邊要跑一次
    {
        ptrace(PTRACE_SINGLESTEP, child, 0, 0);               
        waitpid(child, &status, 0);        
    }

    if(WIFEXITED(status))
    {
        printf("** child process %d terminiated normally (code %d)\n", child, status);
        states = 2;
    }
    else if(WIFSTOPPED(status)) detect_breakpoint(0);
    else printf("** child process error status\n");
}

int main(int argc, char *argv[]) {
    char script[MAXLINE] = "";

    // parse option
    int opt;
    //opterr = 0; // opterr代表就算getopt要不要輸出自己的error message, 0表示不要
    while ((opt = getopt(argc, argv, "s:")) != -1)
    {
        switch (opt) 
        {
            case 's':
                strncpy(script, optarg, strlen(optarg));
                break;
            case '?':  // -s沒給script or 亂給其他參數
                printf("usage: ./hw4 [-s script] [program]\n");
                exit(0);
                break;
        }
    }
    // 經過getopt之後, argv的內容會被調順序, program的位置會在最後

    if(argc == optind + 1) // optind是getopt下一個要檢索的位置, 有給prohram的情況會剩下一個program等著被檢索
        strncpy(program, argv[optind], strlen(argv[optind]));
    
    if(strcmp(program, "") != 0) sdb_load();

    char *cmd, input[MAXLINE];
    FILE *input_file = stdin;
    if(strcmp(script, "") != 0)
    {
        input_file = fopen(script, "r");
        if(input_file == NULL) errquit(script); // 其實應該可以不用處理
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    if(input_file == stdin) printf("sdb> ");
    while(fgets(input, MAXLINE, input_file) != NULL)
    {
        strncpy(input + strlen(input) - 1, "\0", 1); // 去除最後的換行, 用input[strlen(input) - 1] = "\0";會有Warning
        if(strlen(input) == 0)
        {
            if(input_file == stdin) printf("sdb> ");
            continue;
        }

        cmd = strtok(input, " ");
        if(strcmp(cmd, "break") == 0 || strcmp(cmd, "b") == 0)
        {
            char *arg1;
            if((arg1 = strtok(NULL, " ")) == NULL) 
            {
                printf("** no addr is given.\n");
                if(input_file == stdin) printf("sdb> ");
                continue;
            }
            sdb_break(arg1);
        }

        else if(strcmp(cmd, "cont") == 0 || strcmp(cmd, "c") == 0) sdb_cont();

        else if(strcmp(cmd, "delete") == 0)
        {
            char *arg1;
            if((arg1 = strtok(NULL, " ")) == NULL) 
            {
                printf("** no break-point-id is given\n");
                if(input_file == stdin) printf("sdb> ");
                continue;
            }
            sdb_delete(arg1);
        }

        else if(strcmp(cmd, "disasm") == 0 || strcmp(cmd, "d") == 0)
        {
            char *arg1;
            if((arg1 = strtok(NULL, " ")) == NULL) 
            {
                printf("** no addr is given.\n");
                if(input_file == stdin) printf("sdb> ");
                continue;
            }
            sdb_disasm(arg1);
        }
        
        else if(strcmp(cmd, "dump") == 0 || strcmp(cmd, "x") == 0)
        {
            char *arg1;
            if((arg1 = strtok(NULL, " ")) == NULL) 
            {
                printf("** no addr is given.\n");
                if(input_file == stdin) printf("sdb> ");
                continue;
            }
            sdb_dump(arg1);
        }

        else if(strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0) sdb_exit();

        else if(strcmp(cmd, "get") == 0 || strcmp(cmd, "g") == 0)
        {
            char *arg1;
            if((arg1 = strtok(NULL, " ")) == NULL) 
            {
                printf("** no register is given.\n");
                if(input_file == stdin) printf("sdb> ");
                continue;
            }
            sdb_get(arg1);
        }

        else if(strcmp(cmd, "getregs") == 0) sdb_getregs();

        else if(strcmp(cmd, "help") == 0 || strcmp(cmd, "h") == 0) sdb_help();

        else if(strcmp(cmd, "list") == 0 || strcmp(cmd, "l") == 0) sdb_list();

        else if(strcmp(cmd, "load") == 0)
        {
            char *arg1;
            if((arg1 = strtok(NULL, " ")) == NULL) 
            {
                printf("** no register is given.\n");
                if(input_file == stdin) printf("sdb> ");
                continue;
            }
            strncpy(program, arg1, strlen(arg1));
            sdb_load();
        }

        else if(strcmp(cmd, "run") == 0 || strcmp(cmd, "r") == 0) sdb_run();

        else if(strcmp(cmd, "vmmap") == 0 || strcmp(cmd, "m") == 0) sdb_vmmap();

        else if(strcmp(cmd, "set") == 0 || strcmp(cmd, "s") == 0)
        {
            char *arg1, *arg2;
            if((arg1 = strtok(NULL, " ")) == NULL) 
            {
                printf("** Not enough input arguments\n");
                if(input_file == stdin) printf("sdb> ");
                continue;
            }
            if((arg2 = strtok(NULL, " ")) == NULL) 
            {
                printf("** Not enough input arguments\n");
                if(input_file == stdin) printf("sdb> ");
                continue;
            }
            sdb_set(arg1, arg2);
        }

        else if(strcmp(cmd, "si") == 0) sdb_si();

        else if(strcmp(cmd, "start") == 0) sdb_start();

        if(input_file == stdin) printf("sdb> ");
    }

    if(strcmp(script, "") != 0) fclose(input_file);
    
    return 0;       
}