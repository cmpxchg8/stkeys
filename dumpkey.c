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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define PROM_READ     0xC0044400
#define RIP_KEY_LEN   32
#define READ_RIP_KEY  263

typedef struct _ROM_DATA {
    size_t size;
    int code;
    unsigned char data[1024];
} ROM_DATA, *PROM_DATA;

int main(void) {
    int rip, ret, i;
    ROM_DATA rom_dta;
    FILE *out
    
    rom_dta.size = sizeof(rom_dta.data);
    rom_dta.code = READ_RIP_KEY;          // from HomeHub 2

    memset(rom_dta.data, 0, sizeof(rom_dta.data));

    rip = open("/dev/nmon/rip", O_RDWR);

    if (rip < 0) {
        printf("\nCan't open Remote Inventory PROM device.\n");
        return 0;
    }

    ret = ioctl(rip, PROM_READ, &rom_dta);

    printf("\nioctl() returned %08x - %s - Data Size = %i", 
        ret, (ret == 0) ? "OK" : "ERROR", rom_dta.size);

    if (ret == 0 && rom_dta.size == RIP_KEY_LEN) {
      
        printf("\nRIP Key = ");
        
        for (i = 0;i < RIP_KEY_LEN;i++) {
            printf("%02x", rom_dta.data[i]);
        }

        out = fopen("ripkey.bin", "wb");

        if (out != NULL) {
            printf("\n\nSaving data to ripkey.bin...");
            fwrite(&rom_dta.data, 1, sizeof(rom_dta.data), out);
            fclose(out);
            printf("done.\n");
        } else {
            printf("\nUnable to save data to file.\n");
        }
    } else {
        printf("\nError reading data from Remote Inventory PROM device.\n");
    }
    close(rip);
    return 0;
}
