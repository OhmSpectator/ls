#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SYMLINK_SPACER_STR      " -> "
#define TIME_ERROR_STR          "<broken time>"
#define PERMISSIONS_DEFAULT_STR "---------"

#define CTIME_BUFFER_SIZE 26


static void append_linked_name(const struct dirent* entry, char** name)
{
    size_t buffer_size = 1;
    char* buffer = NULL;
    ssize_t symbols_read;

    //Read linked entry name
    while(1) {
        buffer = realloc(buffer, buffer_size);
        symbols_read = readlink(entry->d_name, buffer, buffer_size);
        if(symbols_read < 0) {
            free(buffer);
            return;
        }
        if(symbols_read < buffer_size) {
            buffer[symbols_read] = 0;
            break;
        }
        //symbols_read == buffer_size. Not sure, the whole name is here, retry
        buffer_size *= 2;
    }

    size_t full_name_size = strlen(*name) + strlen(SYMLINK_SPACER_STR) + symbols_read + 1;
    char* result = (char*)malloc(full_name_size);
    if(result == NULL)
        goto cleanup;

    memset(result, 0, full_name_size);
    strcat(result, entry->d_name);
    strcat(result, SYMLINK_SPACER_STR);
    strcat(result, buffer);
    free(*name);
    *name = result;

cleanup:
    free(buffer);

    return;
}

static char* get_name_str(const struct dirent* entry)
{
    char* name_str = NULL;

    name_str = strdup(entry->d_name);
    if(name_str == NULL)
        return name_str;

    struct stat entry_stat;
    int stat_result;
    stat_result = lstat(entry->d_name, &entry_stat);
    if(stat_result < 0)
        return name_str;

    if(S_ISLNK(entry_stat.st_mode))
        append_linked_name(entry, &name_str);

    return name_str;
}

static char get_type_char(const struct stat* entry_stat)
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

static char* get_permissions_str(mode_t mode)
{
    char* permissions_str;
    permissions_str = strdup(PERMISSIONS_DEFAULT_STR);
    if(permissions_str == NULL)
        return NULL;

    if(mode & S_IRUSR)
        permissions_str[0] = 'r';
    if(mode & S_IWUSR)
        permissions_str[1] = 'w';
    if(mode & S_IXUSR)
        permissions_str[2] = 'x';

    if(mode & S_IRGRP)
        permissions_str[3] = 'r';
    if(mode & S_IWGRP)
        permissions_str[4] = 'w';
    if(mode & S_IXGRP)
        permissions_str[5] = 'x';

    if(mode & S_IROTH)
        permissions_str[6] = 'r';
    if(mode & S_IWOTH)
        permissions_str[7] = 'w';
    if(mode & S_IXOTH) {
        if(mode & S_ISVTX)
            permissions_str[8] = 't';
        else
            permissions_str[8] = 'x';
    } else {
        if(mode & S_ISVTX)
            permissions_str[8] = 'T';
    }

    return permissions_str;
}

static char* get_owner_str(uid_t uid)
{
    char* owner_str = NULL;

    struct passwd* user_info = NULL;
    errno = 0;
    user_info = getpwuid (uid);
    if(errno != 0)
        return NULL;

    if(user_info == NULL) {
        size_t len = snprintf(NULL,0, "%ju", (uintmax_t)uid) + 1; //+1 is for '\0'
        owner_str = (char*)malloc(len);
        if(owner_str != NULL)
            sprintf(owner_str, "%ju", (uintmax_t)uid);
    } else {
        owner_str = strdup(user_info->pw_name);
    }

    return owner_str;
}

static char* get_group_str(gid_t gid)
{
    char* group_str = NULL;

    struct group* group_info = NULL;
    errno = 0;
    group_info = getgrgid (gid);
    if(errno != 0)
        return NULL;

    if(group_info == NULL) {
        size_t len = snprintf(NULL,0, "%ju", (uintmax_t)gid) + 1; //+1 is for '\0'
        group_str = (char*)malloc(len);
        if(group_str != NULL)
            sprintf(group_str, "%ju", (uintmax_t)gid);
    } else {
        group_str = strdup(group_info->gr_name);
    }

    return group_str;
}

static char* get_modify_time_str(time_t* time)
{
    char* time_str = NULL;
    char ctime_buffer[CTIME_BUFFER_SIZE];

    char* ctime_result;
    ctime_result = ctime_r(time, ctime_buffer);
    if(ctime_result < 0) {
        time_str = strdup(TIME_ERROR_STR);
    } else {
        size_t len = strlen(ctime_buffer) - 1; //Do not need '\n' at the end
        time_str = strndup(ctime_buffer, len);
    }

    return time_str;
}

static void print_entry(const struct dirent* entry)
{
    char* full_name_str = NULL;
    char* permission_str = NULL;
    nlink_t hardlink_number = 0;
    char* owner_str = NULL;
    char* group_str = NULL;
    off_t bytes = 0;
    char* modify_time_str = NULL;

    struct stat entry_stat;
    int stat_result;
    stat_result = lstat(entry->d_name, &entry_stat);
    if(stat_result < 0) {
        printf("Failed to get stat for %s: %s\n", entry->d_name, strerror(errno));
        goto cleanup;
    }

    char type_char = get_type_char(&entry_stat);

    if(S_ISLNK(entry_stat.st_mode)) {
        stat_result = stat(entry->d_name, &entry_stat);
        if(stat_result < 0) {
            printf("Failed to get stat for %s: %s\n", entry->d_name, strerror(errno));
            goto cleanup;
        }
    }

    full_name_str = get_name_str(entry);
    if(full_name_str == NULL)
        goto cleanup;

    permission_str = get_permissions_str(entry_stat.st_mode);
    if(permission_str == NULL)
        goto cleanup;

    hardlink_number = entry_stat.st_nlink;

    owner_str = get_owner_str(entry_stat.st_uid);
    if(owner_str == NULL)
        goto cleanup;

    group_str = get_group_str(entry_stat.st_gid);
    if(group_str == NULL)
        goto cleanup;

    bytes = entry_stat.st_size;

    modify_time_str = get_modify_time_str(&entry_stat.st_mtime);
    if(modify_time_str == NULL)
        goto cleanup;

    printf("%c%s %ju %s %s %zd %s %s\n",
           type_char, permission_str, (uintmax_t)hardlink_number,
           owner_str, group_str, bytes, modify_time_str, full_name_str);

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
