#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SYMLINK_SPACER_STR " -> "

static char* append_linked_name(const struct dirent* entry)
{
    int buffer_size = 1;
    char* buffer = NULL;
    int symbols_read;
    while(true) {
        buffer = realloc(buffer, buffer_size);
        symbols_read = readlink(entry->d_name, buffer, buffer_size);
        if(symbols_read < 0) {
            free(buffer);
            return NULL;
        }
        if(symbols_read < buffer_size) {
            buffer[symbols_read] = 0;
            break;
        }
        //sumbols_read == buffer_size. Not sure, the whole name is here.
        buffer_size *= 2;
    }
    int full_name_size = strlen(entry->d_name) + strlen(SYMLINK_SPACER_STR) + symbols_read + 1;
    char* result = (char*)malloc(full_name_size);
    memset(result, 0, full_name_size);
    strcat(result, entry->d_name);
    strcat(result, SYMLINK_SPACER_STR);
    strcat(result, buffer);
    free(buffer);
    return result;
}

static char* get_entry_name_str(const struct dirent* entry)
{

    char* full_name = NULL;

    int stat_result;
    struct stat entry_stat;
    stat_result = lstat(entry->d_name, &entry_stat);

    int symlink = S_ISLNK(entry_stat.st_mode);

    if(symlink) {
        full_name = append_linked_name(entry);
    } else {
        full_name = (char*)malloc(strlen(entry->d_name) + 1);
        //TODO check malloc result
        strcpy(full_name, entry->d_name);;
    }
    return full_name;
}

static char get_entry_type_symb(struct stat* entry_stat)
{
    mode_t entry_mode = entry_stat->st_mode;
    int entry_type = entry_mode & S_IFMT;
    switch(entry_type) {
        case S_IFDIR:
            return 'd';
        case S_IFCHR:
            return 'c';
        case S_IFBLK:
            return 'b';
        case S_IFREG:
            return '-';
        case S_IFIFO:
            return 'p';
        case S_IFLNK:
            return 'l';
        case S_IFSOCK:
            return 's';
        default:
            return '?';
    };
}

static char* get_permission_str(const struct stat* entry_stat)
{
    char* permission_str = (char*)malloc(9 + 1);
    memset(permission_str, '-', 9);
    permission_str[9] = 0;

    int mode = entry_stat->st_mode;

    if(mode & S_IRUSR)
        permission_str[0] = 'r';
    if(mode & S_IWUSR)
        permission_str[1] = 'w';
    if(mode & S_IXUSR)
        permission_str[2] = 'x';

    if(mode & S_IRGRP)
        permission_str[3] = 'r';
    if(mode & S_IWGRP)
        permission_str[4] = 'w';
    if(mode & S_IXGRP)
        permission_str[5] = 'x';

    if(mode & S_IROTH)
        permission_str[6] = 'r';
    if(mode & S_IWOTH)
        permission_str[7] = 'w';
    if(mode & S_IXOTH) {
        if(mode & S_ISVTX)
            permission_str[8] = 't';
        else
            permission_str[8] = 'x';
    } else {
        if(mode & S_ISVTX)
            permission_str[8] = 'T';
    }

    return permission_str;
}

static void print_entry(const struct dirent* entry)
{
    unsigned int hardlink_count = 241; //stat->st_nlink
    char* owner = "some_owner"; //stat->st_uid
    char* group = "some_group"; //stat->st_gid
    size_t bytes = 241; //stat->st_size
    const char* last_modify_date = "some_date"; //stat->st_mtime
    unsigned int major = 0, minor = 0;

    struct stat entry_stat;
    int stat_result;
    stat_result = lstat(entry->d_name, &entry_stat);
    //TODO error handling

    char type_symb = get_entry_type_symb(&entry_stat);
    //TODO check for '?' type

    char* full_name_str = get_entry_name_str(entry);
    //TODO error handling

    char* permission_str = get_permission_str(&entry_stat);
    //TODO error handling


    printf("%c%s %u %s %s %zd %s %s\n", type_symb,
               permission_str,
               hardlink_count, owner, group,
               bytes,
               last_modify_date, full_name_str
           );

    free(full_name_str);
    free(permission_str);
}

static int not_a_dot(const struct dirent* entry)
{
    if(entry->d_name[0] == '.')
        return 0;
    else
        return 1;
}

int main(void)
{
    struct dirent** entries;
    int entries_num;
    //XXX implement with scandir64 for LFS
    entries_num = scandir("./", &entries, not_a_dot, alphasort);
    if(entries_num >= 0) {
        for(int i = 0; i < entries_num; i++) {
            print_entry(entries[i]);
            free(entries[i]);
        }
    } else {
        printf("Failed to scan directory: %s\n", strerror(errno));
        return -1;
    }
    free(entries);
    return 0;
}
