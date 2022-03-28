#include <iostream>
#include <unistd.h>
#include <regex>
#include <pwd.h>
#include <dirent.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <map>


#define MAX_LEN 100

using namespace std;

void err_sys(const char* msg)
{
    perror(msg);
    exit(0);
}

class file
{
public:
    string command = "", pid = "", username = "", fd = "", type = "unknown", inode = "", name = "";
private:
};

class my_lsof
{
public:
    void deal_with_option(int argc, char* argv[])
    {
        const char *optstring = "c:t:f:";
        int opt;
        while ((opt = getopt(argc, argv, optstring)) != -1) {
            switch (opt) {
                case 'c':
                    isset_c = true;
                    c_reg_pattern = optarg;
                    break;

                case 't':
                    type = optarg;
                    isset_t = true;
                    if(type != "REG" && type != "CHR" && type != "DIR" && type != "FIFO" && type != "SOCK" && type != "unknown")
                    {
                        printf("Invalid TYPE option.\n");
                        exit(0);
                    }
                    break;

                case 'f':
                    isset_f = true;
                    f_reg_pattern = optarg;
                    break;

                case '?':
                    break;
            }
        } 
    }

    void match_regular_expression()
    {
        /*
        regex_t preg; // 宣告編譯結果變數
        if(regcomp(&preg, c_reg_pattern.c_str(), REG_EXTENDED|REG_ICASE) < 0) // 編譯，這邊使用 ERE，且不考慮大小寫
        {
            printf("regcomp error\n");
            exit(0);
        }

        string target = "testmail_10@gmail.com";   //目標字串
        regmatch_t matchptr[1];   // 記錄匹配結果陣列，長度為1僅記錄 full match
        const size_t nmatch = 1;    //  matchptr陣列長度
        int status = regexec(&preg, target.c_str(), nmatch, matchptr, 0); //匹配
        if (status == REG_NOMATCH){ // 沒匹配
            printf("No Match\n");
        }
        else if (status == 0){  // 匹配
            printf("Match\n");
            printf("\n");
        }
        else {  // 執行錯誤
            char msgbuf[256];
            regerror(status, &preg, msgbuf, sizeof(msgbuf)); 
            printf("error: %s\n", msgbuf);
        }

        regfree(&preg);  // 釋放*/
    }

    void run()
    {
        DIR *dp;
        struct dirent *dirp;
        const char *dir_path = "/proc";
        if((dp = opendir(dir_path)) == NULL)
            err_sys("opendir");

        printf("COMMAND\tPID\tUSER\tFD\tTYPE\tNODE\tNAME\n");

        while((dirp = readdir(dp)) != NULL)
        {
            string pid = dirp -> d_name;
            if(!is_number(pid)) continue;
            deal_with_pid(pid);
        }

        closedir(dp);
    }

    void deal_with_pid(string pid)
    {
        string pid_dir_path = "/proc/" + pid, username = "", command = "";
        char char_command[MAX_LEN];

        struct stat buf;
        if(stat(pid_dir_path.c_str(), &buf) < 0) return;
        username = uid_to_username(buf.st_uid);

        FILE* fd_comm;
        chdir(pid_dir_path.c_str());
        if((fd_comm = fopen("comm", "r")) < 0) return;
        fscanf(fd_comm,"%s", char_command);
        command = char_command;

        //print_file(pid_dir_path, "cwd", "cwd", command, pid, username);
        //print_file(pid_dir_path, "root", "rtd", command, pid, username);
        //print_file(pid_dir_path, "exe", "txt", command, pid, username);
        print_memory_map(pid_dir_path, "maps", "mem", command, pid, username);
    }

    void print_memory_map(string pid_dir_path, string path, string fd, string command, string pid, string username)
    {
        FILE* fd_maps;
        if((fd_maps = fopen(path.c_str(), "r")) < 0) return;
        if(errno == EACCES) return;

        char char_map_file[MAX_LEN] = "", tmp1[MAX_LEN], tmp2[MAX_LEN], tmp3[MAX_LEN], tmp4[MAX_LEN], inode[MAX_LEN] = "";

        cout << pid << "\n";

        while(strcmp(char_map_file, "[heap]") != 0)
        {
            if(fscanf(fd_maps,"%s %s %s %s %s %s", tmp1, tmp2, tmp3, tmp4, inode, char_map_file) < 6) 
                return;
            printf("%s %s %s %s %s %s %s\n", tmp1, tmp2, tmp3, tmp4, inode, char_map_file);
        }
        cout << inode << " " << char_map_file;
        printf("!!!!!!\n");

        while(strcmp(char_map_file, "[stack]") != 0)
        {
            if(fscanf(fd_maps,"%s %s %s %s %s", tmp1, tmp2, tmp3, tmp4, inode) < 5) 
                return;

            if(strcmp(inode, "0") != 0)
                if(fscanf(fd_maps,"%s", char_map_file) < 1)
                    return;


            string map_file = char_map_file, type = "REG";
            if(map_file.find("deleted") != std::string::npos) fd = "DEL";
            

            if(memory_map.count(map_file) != 0) continue;
            memory_map[map_file] = true;

            cout << command << "\t" << pid << "\t" << username << "\t" << fd << "\t" << type << "\t" << inode << "\t" << char_map_file << "\n";
        }
    }

    void print_file(string pid_dir_path, string path, string fd, string command, string pid, string username)
    {
        string inode = "", type = "unknown", filename = "";
        type = get_file_type(path.c_str());
        inode = get_inode(path.c_str());
        filename = get_filename(path.c_str());

        if(type == "" || inode == "" || filename == "") return;

        else if(filename == "permission deny")
            filename = pid_dir_path + "/" + path + " (Permission denied)";

        cout << command << "\t" << pid << "\t" << username << "\t" << fd << "\t" << type << "\t" << inode << "\t" << filename << "\n";
    }

    string get_filename(const char* path)
    {
        char filename[MAX_LEN];
        if(readlink(path, filename, sizeof(filename)) < 0)
        {
            if(errno == EACCES)
                return "permission deny";
            else 
                return "";
        }

        string ans = filename;

        return ans;
    }

    string get_file_type(const char* path)
    {
        struct stat buf;
        string type = "";
        if(stat(path, &buf) < 0) return "";
        switch (buf.st_mode & S_IFMT) {
            case S_IFCHR:  type = "CHR";            break;
            case S_IFDIR:  type = "DIR";            break;
            case S_IFIFO:  type = "FIFO";           break;
            case S_IFREG:  type = "REG";            break;
            case S_IFSOCK: type = "SOCK";           break;
            default:       type = "unknown";        break;
        }

        return type;
    }

    string get_inode(const char* path)
    {
        struct stat buf;
        if(stat(path, &buf) < 0) return "";

        return to_string(buf.st_ino);
    }

    string uid_to_username(int uid)
    {
        return getpwuid(uid) -> pw_name;
    }

    bool is_number(const string& str)
    {
        return str.find_first_not_of("0123456789") == string::npos;
    }

private:
    string type = "", c_reg_pattern = "", f_reg_pattern = "";
    bool isset_t = false , isset_c = false , isset_f = false;
    vector<file> flies;
    map<string, bool> memory_map;
};

int main(int argc, char* argv[])
{
    my_lsof lsof;
    
    lsof.deal_with_option(argc, argv);
    lsof.run();

    return 0;
}