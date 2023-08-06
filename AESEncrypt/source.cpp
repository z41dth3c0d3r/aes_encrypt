#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <wincrypt.h>

typedef struct FILEDATA {
    DWORD dwSize;
    void* lpData;
};

#define BUFFERSIZE 5

DWORD g_BytesTransferred = 0;

void DisplayError(LPTSTR lpszFunction);

VOID CALLBACK FileIOCompletionRoutine(
    __in DWORD dwErrorCode,
    __in DWORD dwNumberOfBytesTransfered,
    __in LPOVERLAPPED lpOverLapped
);

VOID CALLBACK FileIOCompletionRoutine(
    __in DWORD dwErrorCode,
    __in DWORD dwNumberOfBytesTransfered,
    __in LPOVERLAPPED lpOverLapped
) {
    _tprintf(TEXT("Error code:\t%x\n"), dwErrorCode);
    _tprintf(TEXT("Number of bytes:\t%x\n"), dwNumberOfBytesTransfered);
    g_BytesTransferred = dwNumberOfBytesTransfered;
}

FILEDATA ReadFILEDATA(LPCWSTR FileName) {
    FILEDATA fd;

    fd.dwSize = 0;
    fd.lpData = NULL;

    HANDLE hFile;
    hFile = CreateFile(FileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        DisplayError((LPTSTR)TEXT("CreateFile"));
        _tprintf(TEXT("Terminal failure: unable to open file  \"%s\" for read.\n"), FileName);
        return fd;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    fd.dwSize = dwFileSize;
    _tprintf(TEXT("[+] File size of %s is %d\n"), FileName, dwFileSize);
    if (dwFileSize == INVALID_FILE_SIZE) {
        DisplayError((LPTSTR)TEXT("GetFileSize"));
        _tprintf(TEXT("Terminal failure: unable to get the file size.\n"));
        CloseHandle(hFile);
        return fd;
    }
    char* cReadData = new char[dwFileSize + 1];
    DWORD dwBytesRead = 0;
    if (ReadFile(hFile, cReadData, dwFileSize, &dwBytesRead, NULL) == FALSE) {
        DisplayError((LPTSTR)TEXT("ReadFile"));
        _tprintf(TEXT("Terminal failure: unable to read the file.\n"));
        CloseHandle(hFile);
        delete[] cReadData;
        return fd;
    }
    cReadData[dwBytesRead] = '\0';
    fd.lpData = cReadData;

    _tprintf(TEXT("[+] Read %d bytes of data from %s\n"), dwFileSize, FileName);

    CloseHandle(hFile);

    return fd;
}

BOOL WriteDataToFile(FILEDATA fdData) {

    LPCWSTR lpWriteFileName = L"text.base64.txt";

    HANDLE hFile = CreateFile(lpWriteFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        DisplayError((LPTSTR)TEXT("CreateFile"));
        _tprintf(TEXT("Terminal failure: unable to create or open file  \"%s\" for write.\n"), lpWriteFileName);
        return FALSE;
    }

    DWORD dwBytesWritten;

    if (!WriteFile(
        hFile,
        fdData.lpData,
        fdData.dwSize,
        &dwBytesWritten,
        NULL
    )) {
        CloseHandle(hFile);
        return FALSE;
    }
    _tprintf(TEXT("[+] Written %d bytes of data to %s\n"), dwBytesWritten, lpWriteFileName);
    if (dwBytesWritten != fdData.dwSize)
        _tprintf(TEXT("[-] Written size and actual size doesn't match\n"));
    else
        _tprintf(TEXT("[+] Written size and actual size match\n"));
    CloseHandle(hFile);
    return TRUE;
}

FILEDATA Base64Encode(FILEDATA fdData) {
    HCRYPTPROV hCryptProv = 0;
    FILEDATA fd;
    fd.dwSize = 0;
    fd.lpData = NULL;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        DisplayError((LPTSTR)TEXT("CryptAcquireContext"));
        printf("Terminal failure : GetLastError=%08x\n", GetLastError());
        return fd;
    }

    DWORD dwBase64Length = 0;
    if (!CryptBinaryToString((BYTE*)fdData.lpData, fdData.dwSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwBase64Length)) {
        DisplayError((LPTSTR)TEXT("CryptBinaryToString"));
        printf("Terminal failure.\n GetLastError=%08x\n", GetLastError());
        return fd;
    }

    _tprintf(TEXT("[+] Base64 string length : %d bytes\n"), dwBase64Length);

    LPSTR lpBase64 = new char[dwBase64Length + 1];

    if (!CryptBinaryToString((BYTE*)fdData.lpData, fdData.dwSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, (LPWSTR)lpBase64, &dwBase64Length)) {
        DisplayError((LPTSTR)TEXT("CryptBinaryToString"));
        printf("Terminal failure : GetLastError=%08x\n", GetLastError());
        return fd;
    }
    fd.dwSize = dwBase64Length;
    fd.lpData = lpBase64;
    CryptReleaseContext(hCryptProv, 0);

    return fd;
}

int __cdecl _tmain(int argc, TCHAR* argv[]) {

    if (argc != 2) {
        printf("Usage Error: Incorrect number of arguments\n\n");
        _tprintf(TEXT("Usage:\n\t%s <text_file_name>\n"), argv[0]);
        return EXIT_FAILURE;
    }

    FILEDATA lpRawData = ReadFILEDATA(argv[1]);
    if (lpRawData.lpData == NULL) return EXIT_FAILURE;
    FILEDATA lpBase64Ecoded = Base64Encode(lpRawData);
    if (lpBase64Ecoded.lpData == NULL) {
        // delete[] lpRawData.lpData;
        return EXIT_FAILURE;
    }
    // printf("%-20s : 0x%-016p\n", "lpRawData addr", (LPVOID*)lpRawData.lpData);
    // printf("%-20s : 0x%-016p\n", "lpBase64Ecoded addr", (LPVOID*)lpBase64Ecoded.lpData);
    if (WriteDataToFile(lpBase64Ecoded)) {
        printf("[+] Base64Encoded data written successfully!\n");
        // delete lpRawData.lpData;
        // delete lpBase64Ecoded.lpData; // error occurs when trying to free the memory
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;

}

void DisplayError(LPTSTR lpszFunction)
// Routine Description:
// Retrieve and output the system error message for the last-error code
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    lpDisplayBuf =
        (LPVOID)LocalAlloc(LMEM_ZEROINIT,
            (lstrlen((LPCTSTR)lpMsgBuf)
                + lstrlen((LPCTSTR)lpszFunction)
                + 40) // account for format string
            * sizeof(TCHAR));

    if (FAILED(StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error code %d as follows:\n%s"),
        lpszFunction,
        dw,
        lpMsgBuf)))
    {
        printf("FATAL ERROR: Unable to output error code.\n");
    }

    _tprintf(TEXT("ERROR: %s\n"), (LPCTSTR)lpDisplayBuf);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}