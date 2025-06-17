#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include "service.hpp"
#include "hypertech.h"

#undef HIWORD
#undef LOWORD

#define LAST_IND(x,part_type) (sizeof(x)/sizeof(part_type) - 1)
#define HIGH_IND(x,part_type)  LAST_IND(x,part_type)
#define LOW_IND(x,part_type)   0

#define WORDn(x, n)   (*((uint16_t*)&(x)+n))

#define LOWORD(x)  WORDn(x,LOW_IND(x,uint16_t))
#define HIWORD(x)  WORDn(x,HIGH_IND(x,uint16_t))

struct packet {
    int32_t offset;
    uint32_t result_or_arg1;
    uint32_t key;
};

uint32_t hash(uint32_t data) {
    uint32_t salt = 0x77FD097E;
    uint32_t i;
    int32_t tmp;

    for (i = 0; salt; salt >>= 1) {
        if ((salt & 1) != 0)
            i ^= data;
        tmp = data;
        data *= 2;
        if (tmp < 0)
            data ^= 0x357935E9u;
    }
    return i;
}

int16_t transform16(uint16_t value) {
    return 45559 * ((uint32_t)value + 1) % 0x10001 - 1;
}

uint32_t transform32(uint32_t value) {
    uint32_t result = 0; 

    LOWORD(result) = transform16((uint16_t)value);
    HIWORD(result) = transform16(HIWORD(value));
    return result;
}

uint32_t getACLKey(uint32_t magic, uint32_t pid) {
    uint32_t hashed_val = hash(magic + pid);
    return transform32(hashed_val);
}

NTSTATUS send_command(HANDLE hDevice, uint32_t command, int32_t insize, int32_t outsize, packet& structptr) {
    DWORD outSize = 0;
    BOOL success = DeviceIoControl(hDevice, command, &structptr, insize, &structptr, outsize, &outSize, NULL);
    if (!success)
        return GetLastError();
    return 0;
}

/*

0xAA013840 init/handshake
0xAA013884 set bits

0xAA013880 clear bits

0xAA013888 get bits


0xAA0138C0 clears two shits


0xAA0138C4 integrity hash


*/

int main() {
    std::filesystem::path driverPath = std::getenv("TEMP");
    driverPath /= "hypertech.sys";
    std::ofstream o(driverPath, std::ios_base::binary);
    o.write((const char*)rawData, sizeof(rawData));
    o.close();

    service::RegisterAndStart(driverPath.wstring(), L"Hyperfent");
    HANDLE hDevice = CreateFileA("\\\\.\\Htsysm7679", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Couldnt connect to Hyperfent.: %d\n", GetLastError());
        return -1;
    }
    printf("Successfully connected to Hyperfent. Handle: %d, Doing handshake...\n", hDevice);
    packet p{};
    NTSTATUS result = send_command(hDevice, 0xAA013840, 0, 8, p);

    uint32_t magic = p.result_or_arg1;
    printf("Handshake result: %d:%x, Magic value: 0x%x\n", result, result, p.result_or_arg1);

    uint32_t key = getACLKey(magic, GetCurrentProcessId());

    printf("ACL KEY: %x\n", key);
    p.key = key;
    p.offset = 0x5f8;
    p.result_or_arg1 = 0x220000;

    result = send_command(hDevice, 0xAA013884, 12, 4, p);

    printf("Protect process result: %d\n", result);
    CloseHandle(hDevice);
    service::StopAndRemove(L"Hyperfent");
    std::filesystem::remove(driverPath);
    while (true) {
        printf("Im fully protected! Try to access me.\n");
        Sleep(1000);
    }
}