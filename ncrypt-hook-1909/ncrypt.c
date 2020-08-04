#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <ncrypt.h>

#include "../include/setup.h"
#include "../include/runtime.h"
#include "exports.h"

#define MAGIC_NCRYPT_KEY     ((DWORD)0x73736c35)
#define MAGIC_NCRYPT_SSL_KEY ((DWORD)0x44444442)

#define STR_SEPARATOR " "
#define STR_SEPARATOR_SIZE ((DWORD)1)

#define STR_CLIENT_RANDOM "CLIENT_RANDOM "
#define STR_CLIENT_RANDOM_SIZE ((DWORD)14)

#define STR_NEW_LINE "\r\n"
#define STR_NEW_LINE_SIZE ((DWORD)2)

#define ZERO_BUFFER(b) memset(b, 0, sizeof(b));

#pragma warning(disable:4996)

struct NCRYPT_SSL_KEY_S {
	DWORD cbStructLength;
	DWORD dwMagic;
	DWORD dwProtocolVersion;
	DWORD dwUnknown1;
	PVOID pCipherSuiteListEntry;
	DWORD bIsClientCache;
	BYTE rgbMasterSecret[48];
	DWORD dwUnknown2;
};
typedef struct NCRYPT_SSL_KEY_S NCRYPT_SSL_KEY;
typedef NCRYPT_SSL_KEY* PNCRYPT_SSL_KEY;

struct NCRYPT_KEY_S {
	DWORD cbStructLength;
	DWORD dwMagic;
	DWORD unk_1;
	DWORD unk_2;
	PNCRYPT_SSL_KEY pNcryptSslKey;
	PVOID pNcryptSslProvider;
};
typedef struct NCRYPT_KEY_S NCRYPT_KEY;
typedef NCRYPT_KEY* PNCRYPT_KEY;

typedef SECURITY_STATUS(WINAPI* f_SslGenerateMasterKey)(
	_In_  NCRYPT_PROV_HANDLE hSslProvider,
	_In_  NCRYPT_KEY_HANDLE  hPrivateKey,
	_In_  NCRYPT_KEY_HANDLE  hPublicKey,
	_Out_ NCRYPT_KEY_HANDLE* phMasterKey,
	_In_  DWORD              dwProtocol,
	_In_  DWORD              dwCipherSuite,
	_In_  PNCryptBufferDesc  pParameterList,
	_Out_ PBYTE              pbOutput,
	_In_  DWORD              cbOutput,
	_Out_ DWORD*             pcbResult,
	_In_  DWORD              dwFlags
);

typedef SECURITY_STATUS(WINAPI* f_SslImportMasterKey)(
	_In_  NCRYPT_PROV_HANDLE hSslProvider,
	_In_  NCRYPT_KEY_HANDLE  hPrivateKey,
	_Out_ NCRYPT_KEY_HANDLE* phMasterKey,
	_In_  DWORD              dwProtocol,
	_In_  DWORD              dwCipherSuite,
	_In_  PNCryptBufferDesc  pParameterList,
	_In_  PBYTE              pbEncryptedKey,
	_In_  DWORD              cbEncryptedKey,
	_In_  DWORD              dwFlags
);

typedef SECURITY_STATUS(WINAPI* f_SslGenerateSessionKeys)(
	_In_  NCRYPT_PROV_HANDLE hSslProvider,
	_In_  NCRYPT_KEY_HANDLE  hMasterKey,
	_Out_ NCRYPT_KEY_HANDLE* phReadKey,
	_Out_ NCRYPT_KEY_HANDLE* phWriteKey,
	_In_  PNCryptBufferDesc  pParameterList,
	_In_  DWORD              dwFlags
);

typedef SECURITY_STATUS(WINAPI* f_SslExpandTrafficKeys)(
	_In_  NCRYPT_PROV_HANDLE hSslProvider,
	__int64 a2,
	__int64 a3,
	_Out_ NCRYPT_KEY_HANDLE* phReadKey,
	_Out_ NCRYPT_KEY_HANDLE* phWriteKey,
	_In_  PNCryptBufferDesc  pParameterList,
	_In_ DWORD dwFlags
);

f_SslGenerateMasterKey p_f_SslGenerateMasterKey = NULL;
f_SslImportMasterKey p_f_SslImportMasterKey = NULL;
f_SslGenerateSessionKeys p_f_SslGenerateSessionKeys = NULL;
f_SslExpandTrafficKeys p_f_SslExpandTrafficKeys = NULL;

HINSTANCE dll_original = NULL;

extern FARPROC functions[NCRYPT_EXPORTS_COUNT] = { 0 };

BOOL WINAPI DllMain(HINSTANCE dll, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(dll);

		dll_original = LoadLibrary( "C:\\windows\\system32\\ncrypt.orig.dll" );
		if (!dll_original)
		{
			return FALSE;
		}
		for (int i = 0; i < NCRYPT_EXPORTS_COUNT; i++)
		{
			functions[i] = GetProcAddress(dll_original, exports[i]);
		}

		p_f_SslExpandTrafficKeys = (f_SslExpandTrafficKeys)functions[120];
		p_f_SslGenerateMasterKey = (f_SslGenerateMasterKey)functions[129];
		p_f_SslGenerateSessionKeys = (f_SslGenerateSessionKeys)functions[131];
		p_f_SslImportMasterKey = (f_SslImportMasterKey)functions[137];
	} 
	else if (reason == DLL_PROCESS_DETACH)
	{
		FreeLibrary(dll_original);
	}

	return TRUE;
}

PBCryptBuffer get_client_random(PNCryptBufferDesc buffers)
{
	if (buffers == NULL)
	{
		return NULL;
	}

	for (UINT32 i = 0; i < buffers->cBuffers; ++i)
	{
		if (buffers->pBuffers[i].BufferType == NCRYPTBUFFER_SSL_CLIENT_RANDOM)
		{
			return &buffers->pBuffers[i];
		}
	}

	return NULL;
}

HANDLE open_dump_file(VOID)
{
	DWORD pid = GetCurrentProcessId();
	DWORD tid = GetCurrentThreadId();

	CHAR cpid[10];
	ZERO_BUFFER(cpid);
	itoa(pid, cpid, 10);

	CHAR ctid[10];
	ZERO_BUFFER(ctid);
	itoa(tid, ctid, 10);

	CHAR filename[512];
	ZERO_BUFFER(filename);

	strcat(filename, NCRYPT_SSL_KEY_FILE);
	strcat(filename, cpid);
	strcat(filename, ".");
	strcat(filename, ctid);
	strcat(filename, ".txt");

	return CreateFileA(filename, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

VOID dump_master_key(NCRYPT_KEY_HANDLE key, PNCryptBufferDesc buffers)
{
	const PNCRYPT_KEY p_ncrypt_key = (const PNCRYPT_KEY)key;

	// Sanity checks
	if (p_ncrypt_key == NULL || buffers == NULL)
	{
		return;
	}
	if (buffers->pBuffers == NULL)
	{
		return;
	}
	
	const PNCRYPT_SSL_KEY p_ncrypt_ssl_key = (const PNCRYPT_SSL_KEY)(p_ncrypt_key->pNcryptSslKey);
	if (IsBadReadPtr(p_ncrypt_key, sizeof(NCRYPT_KEY)) != 0 || p_ncrypt_key->dwMagic != MAGIC_NCRYPT_KEY ||
		IsBadReadPtr(p_ncrypt_ssl_key, sizeof(NCRYPT_SSL_KEY)) != 0  || p_ncrypt_ssl_key->dwMagic != MAGIC_NCRYPT_SSL_KEY)
	{
		return;
	}

	// Get the client random buffer
	PBCryptBuffer client_random = get_client_random(buffers);
	/*
	if (client_random == NULL)
	{
		return;
	}
	*/

	// Get the heap
	HANDLE heap = GetProcessHeap();

	// Dump
	HANDLE file = INVALID_HANDLE_VALUE;
	LPCSTR client_random_str = NULL;
	LPCSTR key_data_str = NULL;
	__try
	{
		client_random_str = bin2hex(client_random->pvBuffer, client_random->cbBuffer, heap);
		key_data_str = bin2hex((PUCHAR)p_ncrypt_ssl_key->rgbMasterSecret, 48, heap);

		file = open_dump_file();
		if (file == INVALID_HANDLE_VALUE)
		{
			__leave;
		}

		DWORD written = 0;
		WriteFile(file, STR_CLIENT_RANDOM, STR_CLIENT_RANDOM_SIZE, &written, NULL);
		WriteFile(file, client_random_str, (DWORD)strlen(client_random_str), &written, NULL);
		WriteFile(file, STR_SEPARATOR, STR_SEPARATOR_SIZE, &written, NULL);
		WriteFile(file, key_data_str, (DWORD)strlen(key_data_str), &written, NULL);
		WriteFile(file, STR_NEW_LINE, STR_NEW_LINE_SIZE, &written, NULL);
	}
	__finally
	{
		if (file != INVALID_HANDLE_VALUE)
			CloseHandle(file);
		if (client_random_str != NULL)
			HeapFree(heap, 0, (LPVOID)client_random_str);
		if (key_data_str != NULL)
			HeapFree(heap, 0, (LPVOID)key_data_str);
	}
}

extern SECURITY_STATUS WINAPI SslGenerateMasterKey_hook(
	_In_  NCRYPT_PROV_HANDLE hSslProvider,
	_In_  NCRYPT_KEY_HANDLE  hPrivateKey,
	_In_  NCRYPT_KEY_HANDLE  hPublicKey,
	_Out_ NCRYPT_KEY_HANDLE* phMasterKey,
	_In_  DWORD              dwProtocol,
	_In_  DWORD              dwCipherSuite,
	_In_  PNCryptBufferDesc  pParameterList,
	_Out_ PBYTE              pbOutput,
	_In_  DWORD              cbOutput,
	_Out_ DWORD*             pcbResult,
	_In_  DWORD              dwFlags
)
{
	SECURITY_STATUS ret = p_f_SslGenerateMasterKey(hSslProvider, hPrivateKey, hPublicKey, phMasterKey, dwProtocol, dwCipherSuite, pParameterList, pbOutput, cbOutput, pcbResult, dwFlags);

	if (phMasterKey != NULL)
	{
		dump_master_key(*phMasterKey, pParameterList);
	}

	return ret;
}

extern SECURITY_STATUS WINAPI SslImportMasterKey_hook(
	_In_  NCRYPT_PROV_HANDLE hSslProvider,
	_In_  NCRYPT_KEY_HANDLE  hPrivateKey,
	_Out_ NCRYPT_KEY_HANDLE* phMasterKey,
	_In_  DWORD              dwProtocol,
	_In_  DWORD              dwCipherSuite,
	_In_  PNCryptBufferDesc  pParameterList,
	_In_  PBYTE              pbEncryptedKey,
	_In_  DWORD              cbEncryptedKey,
	_In_  DWORD              dwFlags
)
{
	SECURITY_STATUS ret = p_f_SslImportMasterKey(hSslProvider, hPrivateKey, phMasterKey, dwProtocol, dwCipherSuite, pParameterList, pbEncryptedKey, cbEncryptedKey, dwFlags);

	if (phMasterKey != NULL)
	{
		dump_master_key(*phMasterKey, pParameterList);
	}

	return ret;
}

extern SECURITY_STATUS WINAPI SslGenerateSessionKeys_hook(
	_In_  NCRYPT_PROV_HANDLE hSslProvider,
	_In_  NCRYPT_KEY_HANDLE  hMasterKey,
	_Out_ NCRYPT_KEY_HANDLE* phReadKey,
	_Out_ NCRYPT_KEY_HANDLE* phWriteKey,
	_In_  PNCryptBufferDesc  pParameterList,
	_In_  DWORD              dwFlags
)
{
	dump_master_key(hMasterKey, pParameterList);

	return p_f_SslGenerateSessionKeys(hSslProvider, hMasterKey, phReadKey, phWriteKey, pParameterList, dwFlags);
}

extern SECURITY_STATUS WINAPI SslExpandTrafficKeys_hook(
	_In_  NCRYPT_PROV_HANDLE hSslProvider,
	__int64 a2, 
	__int64 a3, 
	_Out_ NCRYPT_KEY_HANDLE* a4,
	_Out_ NCRYPT_KEY_HANDLE* a5,
	_In_  PNCryptBufferDesc  a6,
	_In_ DWORD dwFlags
)
{
	// Get the heap
	HANDLE heap = GetProcessHeap();

	PBCryptBuffer client_random = get_client_random(a6);

	// Dump
	HANDLE file = INVALID_HANDLE_VALUE;
	LPCSTR provider_str = NULL;
	LPCSTR a2_str = NULL;
	LPCSTR a3_str = NULL;
	LPCSTR a4_str = NULL;
	LPCSTR a5_str = NULL;
	LPCSTR a6_str = NULL;
	LPCSTR client_random_str = NULL;
	__try
	{
		file = open_dump_file();
		if (file == INVALID_HANDLE_VALUE)
		{
			__leave;
		}

		provider_str = bin2hex((PUCHAR)hSslProvider, sizeof(PVOID), heap);
		a2_str = bin2hex((PUCHAR)a2, sizeof(PVOID), heap);
		a3_str = bin2hex((PUCHAR)a3, sizeof(PVOID), heap);
		a4_str = bin2hex((PUCHAR)a4, sizeof(PVOID), heap);
		a5_str = bin2hex((PUCHAR)a5, sizeof(PVOID), heap);
		a6_str = bin2hex((PUCHAR)a6, sizeof(PVOID), heap);
		client_random_str = bin2hex(client_random->pvBuffer, client_random->cbBuffer, heap);

		DWORD written = 0;
		WriteFile(file, "SslExpandTrafficKeys ", 20, &written, NULL);
		WriteFile(file, provider_str, (DWORD)strlen(provider_str), &written, NULL);
		WriteFile(file, STR_SEPARATOR, STR_SEPARATOR_SIZE, &written, NULL);
		WriteFile(file, client_random_str, (DWORD)strlen(client_random_str), &written, NULL);
		WriteFile(file, STR_SEPARATOR, STR_SEPARATOR_SIZE, &written, NULL);
		WriteFile(file, a2_str, (DWORD)strlen(a2_str), &written, NULL);
		WriteFile(file, STR_SEPARATOR, STR_SEPARATOR_SIZE, &written, NULL);
		WriteFile(file, a3_str, (DWORD)strlen(a3_str), &written, NULL);
		WriteFile(file, STR_SEPARATOR, STR_SEPARATOR_SIZE, &written, NULL);
		WriteFile(file, a4_str, (DWORD)strlen(a4_str), &written, NULL);
		WriteFile(file, STR_SEPARATOR, STR_SEPARATOR_SIZE, &written, NULL);
		WriteFile(file, a5_str, (DWORD)strlen(a5_str), &written, NULL);
		WriteFile(file, STR_SEPARATOR, STR_SEPARATOR_SIZE, &written, NULL);
		WriteFile(file, a6_str, (DWORD)strlen(a6_str), &written, NULL);
		WriteFile(file, STR_NEW_LINE, STR_NEW_LINE_SIZE, &written, NULL);
	}
	__finally
	{
		if (file != INVALID_HANDLE_VALUE)
			CloseHandle(file);
		if (client_random_str != NULL)
			HeapFree(heap, 0, (LPVOID)client_random_str);
	}

	return p_f_SslExpandTrafficKeys(hSslProvider, a2, a3, a4, a5, a6, dwFlags);
}