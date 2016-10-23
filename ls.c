#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SYMLINK_SPACER_STR " -> "

static char* append_linked_name(const struct dirent* entry)
{
    int buffer_size = 1;
    char* buffer = NULL;
    int symbols_read;
    while(1) {
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
        //symbols_read == buffer_size. Not sure, the whole name is here.
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

static char* get_owner_str(const struct stat* entry_stat)
{
    char* owner_str = NULL;

    uid_t uid = entry_stat->st_uid;

    struct passwd* user_info = NULL;
    user_info = getpwuid (uid);
    
    if(user_info == NULL) {
        char tmp[32];
        sprintf(tmp, "%u", uid);
        size_t len = strlen(tmp);
        owner_str = (char*)malloc(len + 1);
        strcpy(owner_str, tmp);
    } else {
        size_t len = strlen(user_info->pw_name);
        owner_str = (char*)malloc(len + 1);
        strcpy(owner_str, user_info->pw_name);
    }

    return owner_str;
}

static char* get_group_str(const struct stat* entry_stat)
{
    char* group_str = NULL;

    gid_t gid = entry_stat->st_gid;

    struct group* group_info = NULL;
    group_info = getgrgid (gid);
    
    if(group_info == NULL) {
        char tmp[32];
        sprintf(tmp, "%u", gid);
        size_t len = strlen(tmp);
        group_str = (char*)malloc(len + 1);
        strcpy(group_str, tmp);
    } else {
        size_t len = strlen(group_info->gr_name);
        group_str = (char*)malloc(len + 1);
        strcpy(group_str, group_info->gr_name);
    }

    return group_str;
}

static char* get_modify_time_str(const struct stat* entry_stat)
{
    char* time_str = NULL;
    char tmp[100];
    ctime_r(&entry_stat->st_mtime, tmp);
    size_t len = strlen(tmp);
    time_str = (char*)malloc(len);
    strncpy(time_str, tmp, len-1);
    time_str[len-1] = 0;
    return time_str;
}

static void print_entry(const struct dirent* entry)
{

    /* Parts of format string */
    char* full_name_str = NULL;
    char* permission_str = NULL;
    nlink_t hardlink_number = 0;
    char* owner_str = NULL;
    char* group_str = NULL;
    off_t bytes = 0;
    char* modify_time_str = NULL; //stat->st_mtime

    struct stat entry_stat;
    int stat_result;
    stat_result = lstat(entry->d_name, &entry_stat);
    if(stat_result < 0) {
        printf("Failed to get stat for %s: %s\n", entry->d_name, strerror(errno));
        goto cleanup;
    }

    char type_symb = get_entry_type_symb(&entry_stat);
    //TODO check for '?' type
    
    if(S_ISLNK(entry_stat.st_mode))
        stat_result = stat(entry->d_name, &entry_stat);

    full_name_str = get_entry_name_str(entry);
    //TODO error handling

    permission_str = get_permission_str(&entry_stat);
    //TODO error handling

    hardlink_number = entry_stat.st_nlink;

    owner_str = get_owner_str(&entry_stat);
    //TODO error handling

    group_str = get_group_str(&entry_stat);
    //TODO error handling

    bytes = entry_stat.st_size;

    modify_time_str = get_modify_time_str(&entry_stat);
    //TODO error handling

    printf("%c%s %lu %s %s %zd %s %s\n", type_symb,
               permission_str,
               hardlink_number, owner_str, group_str,
               bytes,
               modify_time_str, full_name_str
           );

cleanup:
    if(modify_time_str != NULL)
        free(modify_time_str);
    if(group_str != NULL)
        free(group_str);
    if(owner_str != NULL)
        free(owner_str);
    if(permission_str != NULL)
        free(permission_str);
    if(full_name_str != NULL)
        free(full_name_str);

    return;
}

static int not_a_dot(const struct dirent* entry)
{
    if(entry->d_name[0] == '.')
        return 0;
    else
        return 1;
}

int main(int argc, char* argv[])
{
    int result = EXIT_SUCCESS;
    struct dirent** entries = NULL;
    int entries_num;
    const char* dir = argc > 1 ? argv[1] : "./";
    int chdir_result;
    chdir_result = chdir(dir);
    if(chdir_result < 0) {
        printf("Failed to chdir to %s: %s\n", dir, strerror(errno));
        result = EXIT_FAILURE;
        goto cleanup;
    }
    //XXX implement with scandir64 for LFS
    entries_num = scandir(dir, &entries, not_a_dot, alphasort);
    if(entries_num >= 0) {
        for(int i = 0; i < entries_num; i++) {
            print_entry(entries[i]);
            free(entries[i]);
        }
    } else {
        printf("Failed to scan %s: %s\n", dir, strerror(errno));
        result = EXIT_FAILURE;
        goto cleanup;
    }
cleanup:
    if(entries != NULL)
        free(entries);
    return result;
}
