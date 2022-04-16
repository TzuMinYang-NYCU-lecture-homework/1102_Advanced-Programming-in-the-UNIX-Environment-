#include <iostream>
#include <unistd.h>
#include <regex>
#include <pwd.h>
#include <dirent.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <map>
#include <sstream>


#define MAX_LEN 500

using namespace std;

void err_sys(const char* msg)
{
    perror(msg);
    exit(0);
}

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
                    is_set_c = true;
                    c_reg_pattern = optarg;
                    break;

                case 't':
                    t_type = optarg;
                    
                    is_set_t = true;
                    if(t_type != "REG" && t_type != "CHR" && t_type != "DIR" && t_type != "FIFO" && t_type != "SOCK" && t_type != "unknown")
                    {
                        printf("Invalid TYPE option.\n");
                        exit(0);
                    }
                    break;

                case 'f':
                    is_set_f = true;
                    f_reg_pattern = optarg;
                    break;

                case '?':
                    break;
            }
        } 

        regex c_tmp_reg(c_reg_pattern), f_tmp_reg(f_reg_pattern);
        com_reg = c_tmp_reg;
        file_reg = f_tmp_reg;
    }

    void print(string fd)
    {
        if(match_print())
            cout << command << "\t" << pid << "\t" << username << "\t" << fd << "\t" << type << "\t" << inode << "\t" << filename << "\n";
    }

    bool match_print()
    {
        if(is_set_t && t_type != type) return false;
        if(is_set_c && !regex_search(command, com_reg)) return false;
        if(is_set_f && !regex_search(filename, file_reg)) return false;
        return true;
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
            pid = dirp -> d_name;
            if(!is_number(pid)) continue;
            deal_with_pid();
            memory_map.clear();
        }

        closedir(dp);
    }

    void deal_with_pid()
    {
        pid_dir_path = "/proc/" + pid;
        char char_command[MAX_LEN] = "";

        struct stat buf;
        if(stat(pid_dir_path.c_str(), &buf) < 0) return;
        username = uid_to_username(buf.st_uid);

        FILE* fd_comm;
        chdir(pid_dir_path.c_str());
        if((fd_comm = fopen("comm", "r")) < 0) return;
        fscanf(fd_comm,"%s", char_command);
        command = char_command;

        print_file("cwd", "cwd");
        print_file("root", "rtd");
        print_file("exe", "txt");
        print_memory_map("maps", "mem");
        traverse_fd("fd");

        fclose(fd_comm);
    }
    
    void traverse_fd(string path)
    {
        DIR *dp;
        struct dirent *dirp;
        if((dp = opendir(path.c_str())) == NULL)
        {
            if(errno == EACCES)
            {
                string fd = "NOFD";
                filename = pid_dir_path + "/" + path + " (Permission denied)";
                inode = "";
                type = "";
                print(fd);
            }
                
            return;
        }

        chdir(path.c_str());
        while((dirp = readdir(dp)) != NULL)
        {
            print_fd(dirp -> d_name);
        }

        closedir(dp);
    }
    
    void print_fd(string path)
    {
        set_file_type(path.c_str());
        set_inode(path.c_str());
        set_filename(path.c_str());

        if(type == "" || inode == "" || filename == "") return;

        struct stat buf;
        if(lstat(path.c_str(), &buf) < 0) return;

        string fd = path;
        if(buf.st_mode & S_IRUSR && buf.st_mode & S_IWUSR) fd = fd + "u";
        else if(buf.st_mode & S_IRUSR) fd = fd + "r";
        else if(buf.st_mode & S_IWUSR) fd = fd + "w";
        else fd += "error";

        print(fd);
    }

    void print_memory_map(string path, string fd)
    {
        FILE* fd_maps;
        if((fd_maps = fopen(path.c_str(), "r")) < 0) return;
        if(errno == EACCES) return;

        char char_buffer[MAX_LEN] = "";
        string buffer = "";

        while(buffer.find("[heap]") == std::string::npos)
        {
            if(fgets(char_buffer, MAX_LEN, fd_maps) == NULL) 
                return;
            buffer = char_buffer;
        }
        
        while(buffer.find("[stack]") == std::string::npos)
        {
            if(fgets(char_buffer, MAX_LEN, fd_maps) == NULL) 
                return;
            buffer = char_buffer;

            if(buffer.find("/") == std::string::npos)
                continue;

            string tmp = "";
            type = "REG";
            
            stringstream ss(buffer);
            for(int i = 0; i < 4; i++)  ss >> tmp;
            ss >> inode >> filename;

            if(memory_map.count(filename) != 0) continue;
            memory_map[filename] = true;

            if(buffer.find("deleted") != std::string::npos) fd = "DEL";

            print(fd);
            fd = "mem";
        }

        fclose(fd_maps);
    }

    void print_file(string path, string fd)
    {
        set_file_type(path.c_str());
        set_inode(path.c_str());
        set_filename(path.c_str());

        if(type == "" || inode == "" || filename == "") return;

        else if(filename == "permission deny")
            filename = pid_dir_path + "/" + path + " (Permission denied)";

        if(fd == "txt") memory_map[filename] = true;

        print(fd);
    }

    void set_filename(const char* path)
    {
        char char_filename[MAX_LEN] = "";
        if(readlink(path, char_filename, sizeof(char_filename)) < 0)
        {
            if(errno == EACCES)
                filename = "permission deny";
            else 
                filename = "";
        }

        filename = char_filename;
        if(filename.find("(deleted)") != std::string::npos) filename = filename.substr(0, filename.find("(deleted)"));
    }

    void set_file_type(const char* path)
    {
        struct stat buf;
        if(stat(path, &buf) < 0) type = "";
        switch (buf.st_mode & S_IFMT) {
            case S_IFCHR:  type = "CHR";            break;
            case S_IFDIR:  type = "DIR";            break;
            case S_IFIFO:  type = "FIFO";           break;
            case S_IFREG:  type = "REG";            break;
            case S_IFSOCK: type = "SOCK";           break;
            default:       type = "unknown";        break;
        }
    }

    void set_inode(const char* path)
    {
        struct stat buf;
        if(stat(path, &buf) < 0) inode = "";

        inode = to_string(buf.st_ino);
    }

    string uid_to_username(int uid)
    {
        if(getpwuid(uid) != NULL) return getpwuid(uid) -> pw_name;
        return "";
    }

    bool is_number(const string& str)
    {
        return str.find_first_not_of("0123456789") == string::npos;
    }

private:
    string t_type = "", c_reg_pattern = "", f_reg_pattern = "";
    string command = "", pid_dir_path = "", pid = "", username = "", inode = "", type = "", filename = "";
    bool is_set_t = false , is_set_c = false , is_set_f = false;
    map<string, bool> memory_map;
    regex com_reg, file_reg;
};

int main(int argc, char* argv[])
{
    my_lsof lsof;
    
    lsof.deal_with_option(argc, argv);
    lsof.run();

    return 0;
}