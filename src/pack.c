#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <unistd.h>
#include "globals.h"
#include "config.h"

//! <If external location is used
static bool ext_loc_is_set = false;
static uint8_t ext_loc_path[FILE_NAME_MAX_SZ];

static bool md5_pack_get_md5sum(char *name, uint8_t *md5)
{
    MD5_CTX ctx;
    char buf[512];
    int fd;
    uint64_t bytes;

    bzero(&ctx, sizeof(MD5_CTX));
    MD5_Init(&ctx);

    fd = open((const char *)name, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Unable to open file \'%s\'\n", name);
        return false;
    }

    bytes = (uint64_t)read(fd, buf, sizeof(buf));
    while (bytes > 0) {
        MD5_Update(&ctx, buf, bytes);
        bytes = (uint64_t)read(fd, buf, sizeof(buf));
    }
    MD5_Final(md5, &ctx);
    close(fd);

    return true;
}

static bool md5_pack_verify_path(char *name)
{
    //! <Check argument itself
    if (name == NULL) {
        fprintf(stderr, "Not enough arguments\n");
        return false;
    }
    //! <Check if provided path really exists
    if (access((const char *)name, F_OK) < 0) {
        fprintf(stderr, "File \'%s\' not accessible\n", name);
        return false;
    }

    return true;
}

static bool md5_pack_integrity_check(char *name)
{
    MD5_CTX ctx;
    uint8_t md5[MD5_DIGEST_LENGTH];
    char buf[512];
    uint64_t bytes = 0;
    md5pack header;
    ssize_t ret = 0;
    uint8_t i = 0;
    int fd;

    bzero(&header, sizeof(md5pack));
    fd = open((const char *)name, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Unable to open file \'%s\'\n", name);
        return false;
    }

    ret = read(fd, header.buffer, sizeof(header.buffer));
    if (!(strncmp((const char *)header.msg.header.header_magic,
                  (const char *)MD5PACK_HEADER_MAGIC, MD5PACK_HEADER_MAGIC_SZ))) {
        if (header.msg.header.f_size != 0) {
            //! <Verify checksum in the header with the one, calculating from the file
            bzero(&ctx, sizeof(MD5_CTX));
            bzero(buf, sizeof(buf));

            MD5_Init(&ctx);
            lseek(fd, header.msg.start, SEEK_SET);

            if (header.msg.header.f_size >= sizeof(buf)) {
                bytes = (uint64_t)read(fd, buf, sizeof(buf));
            } else {
                bytes = (uint64_t)read(fd, buf, header.msg.header.f_size);
            }

            while (bytes > 0) {
                MD5_Update(&ctx, buf, bytes);
                bytes = (uint64_t)read(fd, buf, sizeof(buf));
            }
            MD5_Final(md5, &ctx);

            if (!(strncmp((const char *)md5, (const char *)header.msg.header.md5,
                          MD5_DIGEST_LENGTH))) {
                fprintf(stdout, "MD5PACK header found\n"
                                "\tTarget name: %s\n"
                                "\tTarget size: %llu\n"
                                "\tTarget checksum: ",
                        (char *)header.msg.header.f_name,
                        header.msg.header.f_size);
                for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
                    fprintf(stdout, "%02x", header.msg.header.md5[i]);
                }
                fprintf(stdout, "\n");
            } else {
                fprintf(stderr, "Integrity check failed!\n");
                close(fd);
                return false;
            }
        } else {
            //! <Header contains invalid file size.
            //! <TODO: try to recalculate file size and fix the header
            fprintf(stderr, "MD5PACK file corrupt\n");
            close(fd);
            return false;
        }
    } else {
        fprintf(stderr, "\'%s\' is not a valid MD5PACK file. Aborting\n", name);
        close(fd);
        return false;
    }

    close(fd);
    return true;
}

static void md5_pack_extract(char *name)
{
    md5pack header;
    uint64_t size = 0;
    int fd;
    int src_fd;
    bool status = false;
    char target_name[FILE_NAME_MAX_SZ];
    uint8_t read_buffer[4096];
    uint8_t md5[MD5_DIGEST_LENGTH];

    fprintf(stdout, "Extracting file \'%s\'...\nRunning integrity check...\n",
            name);
    status = md5_pack_integrity_check(name);
    if (status) {
        bzero(&header, sizeof(md5pack));
        src_fd = open((const char *)name, O_RDONLY);
        if (src_fd < 0) {
            fprintf(stderr, "Unable to open file \'%s\'\n", name);
            return;
        }

        size = (uint64_t)read(src_fd, header.buffer, sizeof(header.buffer));
        if (size > 0) {
            if (ext_loc_is_set) {
                bzero(target_name, sizeof(target_name));
                snprintf((char *)target_name, sizeof(target_name), "%s/%s",
                        (char *)ext_loc_path, (char *)header.msg.header.f_name);
            } else {
                snprintf((char *)target_name, sizeof(target_name), "%s",
                        (char *)header.msg.header.f_name);
            }

            fd = open((const char *)target_name, O_CREAT | O_RDWR,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
            if (fd < 0) {
                fprintf(stderr, "Unable to create \'%s\' file\n", target_name);
                close(src_fd);
                return;
            }

            lseek(src_fd, header.msg.start, SEEK_SET);

            size = (uint64_t)read(src_fd, read_buffer, sizeof(read_buffer));
            if (size > 0) {
                while (size > 0) {
                    write(fd, read_buffer, size);
                    bzero(read_buffer, sizeof(read_buffer));
                    size = (uint64_t)read(src_fd, read_buffer, sizeof(read_buffer));
                }
            } else {
                fprintf(stderr, "Unable to read the data from the container. "
                                "Aborting\n");
                close(src_fd);
                close(fd);
                return;
            }

            //! <Check target's MD5
            bzero(md5, MD5_DIGEST_LENGTH);
            status = md5_pack_get_md5sum((char *)target_name, md5);
            if (status) {
                if (!(strncmp((const char *)header.msg.header.md5,
                              (const char *)md5, MD5_DIGEST_LENGTH))) {
                    fprintf(stdout, "Success!\n");
                } else {
                    fprintf(stderr, "Failed!\n");
                }
            }
        } else {
            fprintf(stderr, "Unable to get header information from \'%s\'. "
                            "Aborting\n", name);
            close(src_fd);
            return;
        }

        close(src_fd);
        close(fd);
    } else {
        fprintf(stderr, "Integrity check verification failed. Aborting\n");
        return;
    }
}

static void md5_pack_store(char *name)
{
    md5pack header;
    uint64_t size = 0;
    int fd;
    int src_fd;
    bool status = false;
    char target_name[FILE_NAME_MAX_SZ];
    char *str = NULL;
    uint8_t read_buffer[4096];

    fprintf(stdout, "Storing file \'%s\'...\n", name);

    bzero(&header, sizeof(md5pack));
    status = md5_pack_get_md5sum(name, header.msg.header.md5);

    src_fd = open(name, O_RDONLY);
    if (src_fd < 0) {
        fprintf(stderr, "Unable to open file \'%s\'\n", name);
        return;
    }

    size = (uint64_t)lseek(src_fd, 0, SEEK_END);
    close(src_fd);

    snprintf((char *)header.msg.header.header_magic, MD5PACK_HEADER_MAGIC_SZ,
             MD5PACK_HEADER_MAGIC);
    header.msg.header.f_size = size;
    header.msg.start = sizeof(md5pack);
    header.msg.end = header.msg.start + header.msg.header.f_size;
    snprintf((char *)header.msg.header.f_name, sizeof(header.msg.header.f_name),
             "%s", (char *)name);

    bzero(target_name, sizeof(target_name));
    str = strrchr((const char *)name, '.');
    if (str == NULL) {
        //! <It seems that the file doesn't have an extension.
        if (ext_loc_is_set) {
            snprintf(target_name, sizeof(target_name), "%s/%s.%s", ext_loc_path,
                     name, MD5PACK_FILE_EXTENSION);
        } else {
            snprintf(target_name, sizeof(target_name), "%s.%s", name,
                     MD5PACK_FILE_EXTENSION);
        }
    } else {
        if (ext_loc_is_set) {
            snprintf(target_name, name - str, "%s/%s.%s", ext_loc_path, name,
                     MD5PACK_FILE_EXTENSION);
        } else {
            snprintf(target_name, name - str, "%s.%s", name,
                     MD5PACK_FILE_EXTENSION);
        }
    }

    src_fd = open((const char *)name, O_RDONLY);
    if (src_fd < 0) {
        fprintf(stderr, "Unable to open \'%s\'", name);
        return;
    }

    fd = open((const char *)target_name, O_CREAT | O_RDWR,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    if (fd < 0) {
        fprintf(stderr, "Unable to create \'%s\' file", target_name);
        return;
    }

    size = (uint64_t)write(fd, header.buffer, sizeof(header.buffer));
    if (size > 0) {
        while (size > 0) {
            bzero(read_buffer, sizeof(read_buffer));
            size = (uint64_t)read(src_fd, read_buffer, sizeof(read_buffer));
            write(fd, read_buffer, size);
        }
    } else {
        fprintf(stderr, "Unable to write the data to the container. Aborting\n");
        close(src_fd);
        close(fd);
        return;
    }

    close(src_fd);
    close(fd);

    fprintf(stdout, "Running integrity check...\n");
    status = md5_pack_integrity_check(target_name);
    fprintf(stdout, "%s\n", (status) ? "Success!" : "Failed!");
}

static void md5_pack_print_help(void)
{
    fprintf(stdout, "Usage: md5-hashed-pack PARAM file\n"
                    "PARAM:\n"
                    "   -e          extract\n"
                    "   -s          store\n"
                    "   -c          check integrity\n"
                    "   -o          path, where to put the result\n"
                    "   -h          print this help\n"
                    "   -v          print version\n"
                    "\nExample:\n"
                    "\tmd5-hashed-pack -s myfile.ext           will create a myfile.md5pack storage\n"
                    "\tmd5-hashed-pack -s myfile.ext -o /tmp   will create a myfile.md5pack storage within /tmp folder\n"
                    "\tmd5-hashed-pack -e myfile.mpack         will extract original file from storage\n");
}

int main(int argc, char **argv)
{
    uint8_t i = 0;
    char *cmd = NULL;
    bool status = false;

    if (argc == 1) {
        md5_pack_print_help();
    } else if ((argc > 1) && (argc < 6)) {
        for (i = 1; i < 5; i++) {
            cmd = argv[i];
            if (strlen(cmd) > 2) {
                fprintf(stderr, "Invalid command: \'%s\'\n", cmd);
                md5_pack_print_help();
                break;
            }

            if (!(strcmp(cmd, "-v"))) {                                         //! <Print version
                fprintf(stdout, "md5-hashed-pack version %u.%u.%u\n",
                        APP_VERSION_MAJOR, APP_VERSION_MINOR,
                        APP_VERSION_REVISION);
                break;
            } else if (!(strcmp(cmd, "-h"))) {                                  //! <Print help
                md5_pack_print_help();
                break;
            } else if (!(strcmp(cmd, "-e"))) {                                  //! <Extract
                cmd = argv[i + 1];

                if ((argc > 3) && (argc < 6) && (!(strcmp(argv[i + 2], "-o")))) {
                    //! <TODO: check the path is available and writable
                    ext_loc_is_set = true;
                    snprintf((char *)ext_loc_path, sizeof(ext_loc_path),
                             "%s", argv[i + 3]);
                } else {
                    ext_loc_is_set = false;
                }

                if (md5_pack_verify_path(cmd)) {
                    md5_pack_extract(cmd);
                }

                break;
            } else if (!(strcmp(cmd, "-s"))) {                                  //! <Store
                cmd = argv[i + 1];
                if ((argc > 3) && (argc < 6) && (!(strcmp(argv[i + 2], "-o")))) {
                    //! <TODO: check the path is available and writable
                    ext_loc_is_set = true;
                    snprintf((char *)ext_loc_path, sizeof(ext_loc_path),
                             "%s", argv[i + 3]);
                } else {
                    ext_loc_is_set = false;
                }

                if (md5_pack_verify_path(cmd)) {
                    md5_pack_store(cmd);
                }

                break;
            } else if (!(strcmp(cmd, "-c"))) {                                  //! <Integrity check
                cmd = argv[i + 1];
                if (md5_pack_verify_path(cmd)) {
                    fprintf(stdout, "Running integrity check for \'%s\'...\n",
                            cmd);
                    status = md5_pack_integrity_check(cmd);
                    fprintf(stdout, "%s\n", (status) ? "Success!" : "Failed!");
                }

                break;
            }
        }
    } else {
        fprintf(stderr, "Invalid number of arguments\n");
        return -1;
    }

    return 0;
}
