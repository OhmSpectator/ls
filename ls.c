#include <stdio.h>

static int print_file()
{
    char file_type = '-';
    char owner_read = '-', onwer_write = '-', owner_exec = '-';
    char group_read = '-', group_write = '-', group_exec = '-';
    char other_read = '-', other_write = '-', other_exec = '-';
    unsigned int hardlink_count = 241;
    char *owner = "some_owner", *group = "some_group";
    size_t bytes = 241;
    char* last_modify_date = "some_date";
    char* full_name = "maybylink -> somewhere";

    //TODO fix row aligning
    printf("%c %c%c%c %c%c%c %c%c%c %u %s %s %zd %s %s\n", file_type,
            owner_read, onwer_write, owner_exec,
            group_read, group_write, group_exec,
            other_read, other_write, other_exec,
            hardlink_count, owner, group, bytes, last_modify_date, full_name
            );
}

int main()
{
    print_file();
    return 0;
}
