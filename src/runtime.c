#include "../include/runtime.h"

VOID __chkstk(VOID)
{
	return;
}

PVOID memset(PVOID p, INT v, SIZE_T s)
{
	if (p == 0)
	{
		return p;
	}

	PUCHAR _p = (PUCHAR)p;

	for (UINT i = 0; i < s; ++i)
	{
		*_p++ = (CHAR)v;
	}

	return p;
}

SIZE_T strlen(LPCSTR str)
{
	SIZE_T len = 0;

	if (str != NULL)
	{
		while (*str++ != 0)
		{
			++len;
		}
	}

	return len;
}

LPSTR itoa(INT value, LPSTR result, INT base)
{
	if (base < 2 || base > 36) { *result = '\0'; return result; }

	CHAR* ptr = result, * ptr1 = result, tmp_char;
	INT tmp_value, orig_value = value;

	do {
		tmp_value = value;
		value /= base;
		*ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"[35 + (tmp_value - value * base)];
	} while (value);

	if (orig_value < base)
	{
		*ptr++ = 0x30;
	}

	if (tmp_value < 0) *ptr++ = '-';
	*ptr-- = '\0';
	while (ptr1 < ptr) {
		tmp_char = *ptr;
		*ptr-- = *ptr1;
		*ptr1++ = tmp_char;
	}
	return result;
}

LPSTR strcat(LPSTR dst, LPCSTR src)
{
	if (dst == NULL) return dst;
	if (src == NULL) return dst;

	LPSTR _dst = dst;

	for (; *_dst != 0; ++_dst);

	while (*src != 0)
	{
		*_dst++ = *src++;
	}

	return dst;
}

LPCSTR bin2hex(const PUCHAR input, const SIZE_T size, HANDLE heap)
{
	PUCHAR output = (PUCHAR)HeapAlloc(heap, HEAP_ZERO_MEMORY, size * 2 + 1);
	PUCHAR output_iterator = output;
	PUCHAR input_iterator = input;
	LPCSTR hex = "0123456789ABCDEF";

	if (input != NULL)
	{
		for (UINT i = 0; i < size - 1; ++i) {
			*output_iterator++ = hex[(*input_iterator >> 4) & 0xF];
			*output_iterator++ = hex[(*input_iterator++) & 0xF];
		}
		*output_iterator++ = hex[(*input_iterator >> 4) & 0xF];
		*output_iterator++ = hex[(*input_iterator) & 0xF];
		*output_iterator = 0;
	}

	return output;
}