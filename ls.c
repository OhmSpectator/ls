#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void print_entry(const struct dirent* entry)
{
    char file_type = '-';
    char owner_read = '-', onwer_write = '-', owner_exec = '-';
    char group_read = '-', group_write = '-', group_exec = '-';
    char other_read = '-', other_write = '-', other_exec = '-';
    unsigned int hardlink_count = 241;
    char *owner = "some_owner", *group = "some_group";
    size_t bytes = 241;
    const char* last_modify_date = "some_date";
    const char* full_name = entry->d_name;
    unsigned int major = 0, minor = 0; 

    //TODO implement later
    if(file_type == 'c' || file_type == 'b') {
        printf("%c %c%c%c %c%c%c %c%c%c %u %s %s %u, %u %s %s\n", file_type,
               owner_read, onwer_write, owner_exec,
               group_read, group_write, group_exec,
               other_read, other_write, other_exec,
               hardlink_count, owner, group, 
               major, minor, 
               last_modify_date, full_name
              );
    } else {
        printf("%c %c%c%c %c%c%c %c%c%c %u %s %s %zd %s %s\n", file_type,
               owner_read, onwer_write, owner_exec,
               group_read, group_write, group_exec,
               other_read, other_write, other_exec,
               hardlink_count, owner, group, 
               bytes, 
               last_modify_date, full_name
              );
    }
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
        }
    } else {
        printf("Failed to scan directory: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
