#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
 
#define MAX_LEN 20
struct ps_info *trav_dir(char dir[]);
int read_info(char d_name[],struct ps_info *p1);
void print_ps(struct ps_info *head);
int is_num(char *);
void uid_to_name();
 
typedef struct ps_info
{
    char pname[MAX_LEN];
    char user[MAX_LEN];
    int  pid;
    int  ppid;
    char state;
    struct ps_info *next;
}mps;
 
int main(int ac,char *av[])
{
    mps *head,*link;
     
    head=trav_dir("/proc/");
    if(head==NULL)
        printf("traverse dir error\n");
    print_ps(head);
 
    while(head!=NULL)        //釋放連結串列
    {
        link=head;
        head=head->next;
        free(link);
    }
    return 0;
}
 
mps *trav_dir(char dir[])                         
{
    DIR *dir_ptr;
    mps *head,*p1,*p2;
    struct dirent *direntp;
    struct stat infobuf;
 
    if((dir_ptr=opendir(dir))==NULL)
        fprintf(stderr,"dir error %s\n",dir);
    else
    {
        head=p1=p2=(struct ps_info *)malloc(sizeof(struct ps_info));    //建立連結串列
        while((direntp=readdir(dir_ptr)) != NULL)               //遍歷/proc目錄所有程序目錄
        {
            if((is_num(direntp->d_name))==0)                   //判斷目錄名字是否為純數字
            {
                if(p1==NULL)
                {
                    printf("malloc error!\n");
                    exit(0);
                }
 
                if(read_info(direntp->d_name,p1)!=0)         //獲取程序資訊
                {
                    printf("read_info error\n");
                    exit(0);
                }
                p2->next=p1;                        //插入新節點
                p2=p1;
                p1=(struct ps_info *)malloc(sizeof(struct ps_info));
            }
        }
    }
    p2->next=NULL;
    return head;
}
 
int read_info(char d_name[],struct ps_info *p1)
{
    FILE *fd;
    char dir[20];
    struct stat infobuf;
 
    sprintf(dir,"%s/%s","/proc/",d_name);
    chdir("/proc");                        //切換至/proc目錄,不然stat返回-1
    if(stat(d_name,&infobuf)==-1)                     //get process USER
        fprintf(stderr,"stat error %s\n",d_name);
    else
        //p1->user=uid_to_name(infobuf.st_uid);
        uid_to_name(infobuf.st_uid, p1);
 
    chdir(dir);                         //切換到/proc/pid目錄
    if((fd=fopen("stat","r"))<0)
    {
        printf("open the file is error!\n");
        exit(0);       
    }
    while(4==fscanf(fd,"%d %s %c %d\n",&(p1->pid),p1->pname,&(p1->state),&(p1->ppid)))     //讀檔案的前四個欄位內容,並存放在相關的連結串列成員中
    {
        break;                                    
    }
    fclose(fd);
    return 0;
}
 
void uid_to_name(uid_t uid, struct ps_info *p1)         //由程序uid得到程序的所有者user
{
    struct passwd *getpwuid(), *pw_ptr;
    static char numstr[10];
 
    if((pw_ptr=getpwuid(uid)) == NULL)
    {
        sprintf(numstr,"%d",uid);
        strcpy(p1->user, numstr);
    }
    else
        strcpy(p1->user, pw_ptr->pw_name);
}
 
int is_num(char p_name[])
{
    int i,len;
    len=strlen(p_name);
    if(len==0) return -1;
    for(i=0;i<len;i++)
        if(p_name[i]<'0' || p_name[i]>'9')
            return -1;
    return 0;
}
 
void print_ps(struct ps_info *head)
{
    mps *list;
    printf("USER\t\tPID\tPPID\tSTATE\tPNAME\n");
    for(list=head;list!=NULL;list=list->next)
    {
        printf("%s\t\t%d\t%d\t%c\t%s\n",list->user,list->pid,list->ppid,list->state,list->pname);
    }
}