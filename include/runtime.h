#pragma once

#define WINDOWS_LEAN_AND_MEAN
#include <windows.h>

VOID __chkstk(VOID);

PVOID memset(PVOID p, INT v, SIZE_T s);

SIZE_T strlen(LPCSTR str);

LPSTR itoa(INT value, LPSTR result, INT base);

LPSTR strcat(LPSTR dst, LPCSTR src);

LPCSTR bin2hex(const PUCHAR input, const SIZE_T size, HANDLE heap);