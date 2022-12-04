#include <mbedtls/aes.h>
#include <mbedtls/sha1.h>
#include <iostream>
#include <string>
#include <cmath>
#include <fstream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <unistd.h>
#include <cstring>

#include <tmd.h>

#define BSWAP_8(x) ((x) &0xff)

inline uint16_t bswap_16(uint16_t value) {
    return (uint16_t) ((0x00FF & (value >> 8)) | (0xFF00 & (value << 8)));
}

inline uint32_t bswap_32(uint32_t __x) {
    return __x >> 24 | __x >> 8 & 0xff00 | __x << 8 & 0xff0000 | __x << 24;
}

inline uint64_t bswap_64(uint64_t x) {
    return (((x & 0xff00000000000000ull) >> 56) | ((x & 0x00ff000000000000ull) >> 40) | ((x & 0x0000ff0000000000ull) >> 24) | ((x & 0x000000ff00000000ull) >> 8) | ((x & 0x00000000ff000000ull) << 8) | ((x & 0x0000000000ff0000ull) << 24) | ((x & 0x000000000000ff00ull) << 40) | ((x & 0x00000000000000ffull) << 56));
}

std::ifstream::pos_type filesize(const char* filename)
{
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg(); 
}

static const unsigned char *wiiu_common_key = "";
static unsigned char encrypted_titlekey[33] = "";

int main() {
    static unsigned char decrypted_titlekey[33];
    TMD *tmdData = (TMD *)malloc(sizeof(TMD));
    memset(tmdData, 0, sizeof(TMD));
    FILE *tmdFile = fopen("title.tmd", "rb");

    fread(tmdData, sizeof(TMD), 1, tmdFile);

    printf("tid: %016llx\n", bswap_64(tmdData->tid));

    fclose(tmdFile);

    mbedtls_aes_context aes;
    mbedtls_aes_setkey_dec(&aes, (const unsigned char*)wiiu_common_key, 128);
    unsigned char titleID[16];
    sprintf(titleID, "%016llx", bswap_64(tmdData->tid));
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, titleID, encrypted_titlekey, decrypted_titlekey);
    printf("Decrypted Titlekey: %s\n", decrypted_titlekey);

    uint16_t contentCount = bswap_16(tmdData->num_contents);
    char outputName[255];
    char idChar[255];
    for (int i = 0; i < contentCount; ++i) {
        uint32_t id = bswap_32(tmdData->contents[i].cid);
        snprintf(outputName, sizeof(outputName), "%08X.h3", id);
        snprintf(idChar, sizeof(idChar), "%08x.app", id);
        if (bswap_16(tmdData->contents[i].type) & TMD_CONTENT_TYPE_HASHED) {
            unsigned char h3_hashes[20];
            size_t left = filesize(idChar);
            size_t chunkCount = floor(left / 0x10000);

            size_t h0_hash_num = 0;
            size_t h1_hash_num = 0;
            size_t h2_hash_num = 0;
            size_t h3_hash_num = 0;

            FILE *encrypted = fopen(idChar, "rb");
            if(encrypted == nullptr) {
                snprintf(idChar, sizeof(idChar), "%08X.app", id);
                encrypted = fopen(idChar, "rb");
                if(encrypted == nullptr) {
                    fprintf(stderr, "Couldn't find file with id %08X\n", id);
                    exit(1);
                }
            }
            for(size_t chunkNum = 0; chunkCount < chunkNum; ++chunkNum) {
                mbedtls_aes_context ctx;
                mbedtls_aes_init(&ctx);
                mbedtls_aes_setkey_dec(&ctx, decrypted_titlekey, 128);
                unsigned char iv[16];
                std::fill(iv, iv + 16, 0x00);
                unsigned char hash_tree[0x400];
                fread(hash_tree, 0x400, 1, encrypted);
                mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, 0x400, iv, hash_tree, hash_tree);
                unsigned char h0_hashes[0x140];
                unsigned char h1_hashes[0x140];
                unsigned char h2_hashes[0x140];
                memcpy(h0_hashes, hash_tree, 0x140);
                memcpy(h1_hashes, hash_tree + 0x140, 0x140);
                memcpy(h2_hashes, hash_tree + 0x280, 0x140);
                unsigned char h0_hash[0x14];
                unsigned char h1_hash[0x14];
                unsigned char h2_hash[0x14];
                memcpy(h0_hash, h0_hashes + (h0_hash_num * 0x14), 0x14);
                memcpy(h1_hash, h1_hashes + (h1_hash_num * 0x14), 0x14);
                memcpy(h2_hash, h2_hashes + (h2_hash_num * 0x14), 0x14);
                mbedtls_aes_free(&ctx);
                unsigned char hashesHash[20];
                mbedtls_sha1(h0_hashes, 320, hashesHash);
                if(hashesHash != h1_hash)
                    printf("\rH0 Hashes invalid in chunk %zu", chunkNum);
                mbedtls_sha1(h1_hashes, 320, hashesHash);
                if(hashesHash != h2_hash)
                    printf("\rH1 Hashes invalid in chunk %zu", chunkNum);
                mbedtls_sha1(h2_hashes, strlen(h2_hashes), hashesHash);

                if (memcmp(hashesHash, h3_hashes, 20) != 0) {
                    memcpy(h3_hashes, hashesHash, 20);
                }
                memcpy(iv, h0_hash, 0x10);
                mbedtls_aes_context aes_ctx;
                mbedtls_aes_init(&aes_ctx);
                mbedtls_aes_setkey_dec(&aes_ctx, decrypted_titlekey, 256);

                unsigned char decrypted_data[0xFC00];
                unsigned char encrypted_data[0xFC00];

                size_t read = fread(encrypted_data, 1, 0xFC00, encrypted);
                mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, read, iv, encrypted_data, decrypted_data);

                mbedtls_sha1(decrypted_data, 0xFC00, hashesHash);
                if(hashesHash != h0_hash)
                    printf("\rData block hash invalid in chunk %zu", chunkNum);
                
                h0_hash_num++;
                if(h0_hash_num >= 16) {
                    h0_hash_num = 0;
                    h1_hash_num++;
                }
                if(h1_hash_num >= 16) {
                    h1_hash_num = 0;
                    h2_hash_num++;
                }
                if(h2_hash_num >= 16) {
                    h2_hash_num = 0;
                    h3_hash_num++;
                }
            }
            FILE *h3 = fopen(outputName, "wb");
            fwrite(h3_hashes, 20, 1, h3);
            fclose(h3);
        }
    }

    return 0;
}