/**
 *  The MIT License:
 *
 *  Copyright (c) 2012 Kevin Devine, James Hall
 *
 *  Permission is hereby granted,  free of charge,  to any person obtaining a 
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction,  including without limitation 
 *  the rights to use,  copy,  modify,  merge,  publish,  distribute,  
 *  sublicense,  and/or sell copies of the Software,  and to permit persons to 
 *  whom the Software is furnished to do so,  subject to the following 
 *  conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED,  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER
 *  LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,  TORT OR OTHERWISE,  
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
 *  OTHER DEALINGS IN THE SOFTWARE.
 */
#include <stdint.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define BT_KEY_LEN      10
#define BT_PASS_LEN     8
#define BT_SSID_LEN     4

#define PRODUCT_NBR_LEN 12
#define RIP_KEY_LEN     32

#define BIN2HEX(x) (x < 10) ? (x + '0') : (x + '7')
#define HEX2BIN(x) (x - '0' < 10) ? (x - '0') : (x - '7')

/**
 *  return 4-bit checksum of product
 *
 *  product[]  : 12-byte string
 *
 */
uint32_t chksum(char product[]) {
    uint32_t sum = 16;
    int i;
    
    for (i = 0; i < PRODUCT_NBR_LEN - 1; i++) {
        sum += HEX2BIN(product[i]);
        sum = (sum >= 17) ? (sum - 16) : sum;

        sum <<= 1;
        sum = (sum >= 17) ? (sum - 17) : sum;
    }

    sum = (17 - sum);
    return (sum != 16) ? sum : 0;
}

/**
 *  generate product number from RIP key
 *
 *  product[]  : buffer for 12 byte string
 *  rip_key[]  : 256-bit key from flash memory
 *
 */
void ripkey2product(char product[], uint8_t rip_key[]) {
    uint8_t dgst[20];
    SHA_CTX ctx;
    int i, j;
    
    product[PRODUCT_NBR_LEN] = 0;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, rip_key, RIP_KEY_LEN);
    SHA1_Update(&ctx, "WLAN", 4);
    SHA1_Final(dgst, &ctx);

    for (i = 0, j = 0; i < PRODUCT_NBR_LEN / 2; i++) {
        product[j++] = BIN2HEX((dgst[i] >> 4));
        product[j++] = BIN2HEX((dgst[i] & 0xF));
    }
    product[11] = BIN2HEX(chksum(product));
}

/**
 *  generate default WEP/WPA key
 *
 *  key[]  : buffer for 10-byte string
 *  dgst[] : SHA-1 hash
 *
 */
char *bt_key(char key[], uint8_t dgst[]) {
    const char *format = "23456789abcdef";
    size_t tbl_len = strlen(format);
    uint32_t x1, x2, r;
    int i;
    
    key[BT_KEY_LEN] = 0;
        
    // use 40 bits
    x1  = dgst[2] | (dgst[1] << 8) | (dgst[0] << 16);
    x2  = dgst[4] | (dgst[3] << 8);

    for (i = BT_KEY_LEN - 1; i >= 0; --i) {
        r = ((x2 + ((x1 % tbl_len) << 16)) % tbl_len);

        key[i] = format[r];

        if (x2 < r) {
            x1--;
            x2++;
        }

        x2 -= r;
        x2 += ((x1 % tbl_len) << 16);

        x1 /= tbl_len;
        x2 /= tbl_len;
    }
    return key;
}

/**
 *  generate default SSID for BT HomeHub 2
 *
 *  ssid[] : buffer for 4-byte string
 *  dgst[] : SHA-1 hash
 *
 */
char* bt_ssid(char ssid[], uint8_t dgst[]) {
    const char *format = "23456789CFGHJKMNPQRSTWZ";
    size_t tbl_len = strlen(format);
    uint32_t x1;
    int i;
    
    ssid[BT_SSID_LEN] = 0;

    // use last 20 bits
    x1  = dgst[19] | (dgst[18] << 8) | (dgst[17] & 0xF) << 16;

    for (i = BT_SSID_LEN - 1; i >= 0; --i) {
        ssid[i] = format[x1 % tbl_len];
        x1 /= tbl_len;
    }
    return ssid;
}

/**
 *  generate default Admin password for BT HomeHub 2
 *
 *  passw[]    : buffer for 8-byte string
 *  rip_key[]  : 256-bit key from flash memory
 *
 */
char *bt_passw(char passw[], uint8_t rip_key[]) {
    const char *format = "0123456789ACEFGHJKMNPQRSTWYZ";
    size_t tbl_len = strlen(format);
    char key[RIP_KEY_LEN*2];
    uint8_t dgst[20];
    uint32_t p1, p2;
    SHA_CTX ctx;
    int i, j;
    
    passw[BT_PASS_LEN] = 0;
    memset(key, 0, sizeof(key));

    for (i = 0, j = 0; i < RIP_KEY_LEN; i++) {
        key[j++] = BIN2HEX((rip_key[i] >> 4));
        key[j++] = BIN2HEX((rip_key[i] & 0xF));
    }

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, key, RIP_KEY_LEN * 2);
    SHA1_Update(&ctx, "admin", 5);
    SHA1_Final(dgst, &ctx);

    p1 = (dgst[2] | (dgst[1] << 8) | (dgst[0] << 16)) << 4;
    p2 = (dgst[5] | (dgst[4] << 8) | (dgst[3] << 16)) >> 4;

    for (i = BT_PASS_LEN - 1; i >= 0; --i) {
       p2 += ((p1 % tbl_len) << 16);
       p1 /= tbl_len;
       passw[i] = format[p2 % tbl_len];
       p2 /= tbl_len;
    }
    return passw;
}

void genkeys(uint8_t rip_key[], char serial[]) {
    char product[PRODUCT_NBR_LEN+1];
    SHA_CTX ctx;
    uint8_t dgst[20];
    int i, j;
    char key[BT_KEY_LEN+1], ssid[BT_SSID_LEN+1], passw[BT_PASS_LEN+1];

    if (serial != 0) {
        for (i = 0; i < 6; i++) {
            product[i] = toupper((int)serial[i]);
        }

        for (i = 0, j = 6; i < 3; i++) {
            product[j++] = BIN2HEX((toupper((int)serial[8+i]) >> 4));
            product[j++] = BIN2HEX((toupper((int)serial[8+i]) & 0xF));
        }
      } else {
        printf("\n  RIP Key  : ");

        for (i = 0; i < RIP_KEY_LEN; i++) {
            printf("%02x", rip_key[i]);
        }
        ripkey2product(product, rip_key);
    }

    printf("\n  Serial   : %s\n", product);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, product, PRODUCT_NBR_LEN);
    SHA1_Final(dgst, &ctx);

    // Thomson format
    printf("\n  SSID     : SpeedTouch%02X%02X%02X",
        dgst[17], dgst[18], dgst[19]);

    printf("\n  WPA/WEP  : %02X%02X%02X%02X%02X\n",
        dgst[ 0], dgst[ 1], dgst[ 2], dgst[3], dgst[4]);

    // British Telecom format
    printf("\n  SSID     : BTHomeHub2-%s", bt_ssid(ssid, dgst));
    printf("\n  WPA/WEP  : %s",            bt_key(key, dgst));
    printf("\n  Password : %s\n\n",
         (rip_key != 0) ? bt_passw(passw, rip_key) : "N/A");
}

uint8_t key1[RIP_KEY_LEN] = { 0xd0, 0x7f, 0x92, 0xee, 0x7f, 0x24, 0xa2, 0x47,
                              0x61, 0x68, 0x80, 0x28, 0x53, 0x35, 0x94, 0x02,
                              0xba, 0x5b, 0x2a, 0x48, 0x7c, 0xbd, 0x4d, 0xff,
                              0xa7, 0xd3, 0xcb, 0xa2, 0x52, 0x05, 0x60, 0xf8 };

uint8_t key2[RIP_KEY_LEN] = { 0xdf, 0x94, 0x30, 0xc0, 0x27, 0x40, 0x74, 0xa3,
                              0x63, 0x21, 0xe3, 0xac, 0x80, 0xed, 0x60, 0x00,
                              0xe3, 0x7d, 0x6e, 0xfa, 0xe1, 0xe1, 0x02, 0xc4,
                              0x3f, 0x9c, 0x67, 0x47, 0x64, 0x99, 0xcb, 0x50 };

int main(int argc, char *argv[]) {
    struct stat fs = {0};
    int ret;
    FILE *fd;
    uint8_t rip_key[RIP_KEY_LEN];
    
    puts("\n  Thomson Router Key Generator v1.0"
         "\n  Copright (c) 2012 Kevin Devine and James Hall\n");

    // argument can be serial number or binary file with RIP key in it
    if (argc == 2) {
      // check for rip key first
      if (stat(argv[1], &fs) == 0) {
        if (fs.st_size != 1024) {
            printf("\n  RIP dump should should be 1024 bytes exactly"
                   " - %s is %lld bytes", argv[1], fs.st_size);
            exit(-1);
        }

        fd = fopen(argv[1], "rb");

        if (fd == NULL) {
            perror(argv[1]);
        }

        ret = fread(rip_key, 1, RIP_KEY_LEN, fd);
        fclose(fd);

        if (ret != RIP_KEY_LEN) {
            printf("\nRead error of %s", argv[1]);
            exit(-1);
        }
        genkeys(rip_key, 0);
      } else if (strlen(argv[1]) == 11 &&
                 toupper((int)argv[1][0]) == 'C' &&
                 toupper((int)argv[1][1]) == 'P') {
        genkeys(0, argv[1]);

      } else {
          printf("\n  Usage: stkeygen <serial> | <ripkey.bin>\n\n");
          exit(-1);
      }
    } else {
        genkeys(key1, 0);
        genkeys(key2, 0);
    }
    return 0;
}
