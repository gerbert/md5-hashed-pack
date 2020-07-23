#ifndef INCLUDE_GLOBALS_H_
#define INCLUDE_GLOBALS_H_

#include <stdio.h>
#include <inttypes.h>
#include <openssl/md5.h>
#include <string.h>

#define FILE_NAME_MAX_SZ        255                             //! <File name maximum length
#define FILE_WR_BLOCK_SZ        4096                            //! <Write size
#define MD5PACK_HEADER_MAGIC    "MD5PACK"                       //! <Header magic
#define MD5PACK_FILE_EXTENSION  "md5pack"                       //! <Extension used for storing procedure
#define MD5PACK_HEADER_MAGIC_SZ 8                               //! <Header magic size

#pragma pack(push, 1)
typedef struct {
        uint8_t         header_magic[MD5PACK_HEADER_MAGIC_SZ];  //! <Header ID
        uint16_t        f_name[FILE_NAME_MAX_SZ];               //! <File name
        uint64_t        f_size;                                 //! <File size
        uint8_t         md5[MD5_DIGEST_LENGTH];                 //! <Target's checksum
} md5pack_header;

typedef union {
        struct _md5pack {
                md5pack_header header;                          //! <Header
                uint16_t start;                                 //! <BOF
                uint64_t end;                                   //! <EOF
        } msg;
        uint8_t buffer[sizeof(struct _md5pack)];
} md5pack;
#pragma pack(pop)

#endif /* INCLUDE_GLOBALS_H_ */
