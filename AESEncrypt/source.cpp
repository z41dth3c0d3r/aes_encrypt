#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <tchar.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


#define DATA_TO_ENCRYPT  "Test Data"

#define KEY_LEN 16


const BYTE rgbPlaintext[] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const BYTE rgbIV[] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const BYTE rgbAES128Key[] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

void PrintBytes(IN BYTE* pbPrintData, IN DWORD cbDataLen)
{
    DWORD dwCount = 0;

    for (dwCount = 0; dwCount < cbDataLen;dwCount++)
    {
        printf("0x%02x, ", pbPrintData[dwCount]);

        if (0 == (dwCount + 1) % 10) putchar('\n');
    }

}

PBYTE ReadFileData(LPTSTR lptFileName) {
    HANDLE hFile;
    PBYTE pbFileData = NULL;

    hFile = CreateFile(lptFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error opening the input file.\n");
        return NULL;
    }
    _tprintf(TEXT("[+] Opened the file \"%s\" successfully.\n"), lptFileName);

    DWORD cbinputFileSize = GetFileSize(hFile, NULL);
    if (cbinputFileSize == INVALID_FILE_SIZE) {
        printf("[-] Error getting input file size.\n");
        CloseHandle(hFile);
        return NULL;
    }

    pbFileData = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cbinputFileSize + 1) * sizeof(char)));

    if (!pbFileData) {
        printf("[-] Error occured when allocating memory in heap.\n");
        CloseHandle(hFile);
        return NULL;
    }

    printf("[+] Size of the file : %d bytes.\n", cbinputFileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, pbFileData, cbinputFileSize, &bytesRead, NULL)) {
        printf("[-] Error reading from the input file.\n");
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, pbFileData);
        return NULL;
    }

    pbFileData[cbinputFileSize] = '\0';

    printf("[+] Read bytes from the input file : %d bytes.\n", bytesRead);
    CloseHandle(hFile);


    return pbFileData;
}

BOOL WriteDataToFile(PBYTE pbData, LPTSTR lptWriteFileName) {
    HANDLE hFile = CreateFile(lptWriteFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("[-] Unable to create or open file  \"%s\" for write.\n"), lptWriteFileName);
        return FALSE;
    }

    DWORD cbBytesWritten = 0;
    DWORD cbBytesToWrite = static_cast<DWORD>(strlen((const char*)pbData) * sizeof(char));

    if (!WriteFile(
        hFile,
        pbData,
        cbBytesToWrite,
        &cbBytesWritten,
        NULL
    )) {
        CloseHandle(hFile);
        return FALSE;
    }

    _tprintf(TEXT("[+] Written bytes to file \"%s\": %d bytes.\n"), lptWriteFileName, cbBytesWritten);

    if (cbBytesWritten != cbBytesToWrite)
        printf("[-] Written size and actual size doesn't match.\n");
    else
        printf("[+] Written size and actual size match.\n");

    CloseHandle(hFile);

    printf("[+] Successfully writen the Base64 encoded data to file.\n");


    return TRUE;
}

PBYTE GenerateRandomBytes(ULONG cbKyeLen)
{
    BCRYPT_ALG_HANDLE hRngAlgorithm = NULL;

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    status = BCryptOpenAlgorithmProvider(
        &hRngAlgorithm,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0
    );
    if (!NT_SUCCESS(status)) {
        _tprintf(TEXT("[-] Error code 0x%x returned by BCryptOpenAlgorithmProvider.\n"), status);
        return NULL;
    }

    PBYTE pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKyeLen);
    if (NULL == pbIV) {
        _tprintf(TEXT("[-] Memory allocation to store random key failed.\n"));
        BCryptCloseAlgorithmProvider(hRngAlgorithm, 0);
        return NULL;
    }

    status = BCryptGenRandom(hRngAlgorithm, pbIV, cbKyeLen, 0);

    if (!NT_SUCCESS(status)) {
        _tprintf(TEXT("[-] Error code 0x%x returned by BCryptGenRandom.\n"), status);
        BCryptCloseAlgorithmProvider(hRngAlgorithm, 0);
        HeapFree(GetProcessHeap(), 0, pbIV);
        return NULL;
    }

    BCryptCloseAlgorithmProvider(hRngAlgorithm, 0);

    return pbIV;
}

void PrintUsage(void)
{
    printf("\nUsage : aes.exe [options]\n\n");
    printf("Options\n");
    printf("-------\n");
    printf("\t -i [path_to_file]        : Input data from a file.\n");
    printf("\t -iS [input_data]         : Input data from command line.\n");
    printf("\t -o [output_file_name]    : Output file name.\n");
    printf("\t -oS                      : Output will be printed on screen.\n");
    printf("\t -e                       : To encode the data to base64.\n");
    printf("\t -d                       : To decode the data from base64.\n");
}

/*
  
  max 8 input
  min 6 input

    get data from a file or command line -i or -iS
    get a key from file or command line for generate symmetricKey -k or -kS or -kG to generate key
    get output location -o or -oS
    encryption or decryption -e or -d

    assumptions:
        only 128bit key used
        if user provide more than 16 bytes key than only the 16 bytes of the key used
        if the key shorted than 16 bytes than random bytes added until it becomes 16 bytes
        than BCryptGenerateSymmetricKey used to generate the key

        first input encoded into base64 and than aes encryption begin
        also result from encrytion base64 encoded!

        only decryption returns original data


*/

PBYTE WideCharToPByte(LPTSTR lptData) {
    int iWideStrLen = _tcslen(lptData);

    int iUtf8Len = WideCharToMultiByte(CP_UTF8, 0, lptData, iWideStrLen, NULL, 0, NULL, NULL);
    if (iUtf8Len == 0) {
        _tprintf(TEXT("[-] Wide char to multi byte conversion failed.\n"));
        return NULL;
    }

    PUCHAR pucData = new UCHAR[iUtf8Len + 1];
    
    if (WideCharToMultiByte(CP_UTF8, 0, lptData, iWideStrLen, reinterpret_cast<LPSTR>(pucData), iUtf8Len, NULL, NULL) == 0) {
        _tprintf(TEXT("[-] Wide char to multi byte conversion failed.\n"));
        delete[] pucData;
        return NULL;
    }

    pucData[iUtf8Len] = '\0';

    return pucData;
}

LPTSTR PByteToWideChar(PBYTE pbData) {
    int utf8StringLength = static_cast<int>(strlen(reinterpret_cast<const char*>(pbData)));

    int wideLength = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(pbData), utf8StringLength, NULL, 0);
    if (wideLength == 0) {
        _tprintf(TEXT("[-] Conversion failed.\n"));
        return NULL;
    }

    LPTSTR lptData = new TCHAR[wideLength + 1];
    if (MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(pbData), utf8StringLength, lptData, wideLength) == 0) {
        _tprintf(TEXT("[-] Conversion failed.\n"));
        delete[] lptData;
        return NULL;
    }

    lptData[wideLength] = TEXT('\0');

    return lptData;
}

PBYTE Encrypt(PBYTE pbPlainText, BCRYPT_KEY_HANDLE hKey) {

}




int _tmain(int argc, TCHAR *argv[])
{
    if (argc < 6 || argc > 10) {
        PrintUsage();
        return EXIT_SUCCESS;
    }

    BOOL bInputFromFile = FALSE;
    BOOL bOutputToFile = FALSE;
    BOOL bKeyGenerate = FALSE;
    BOOL bInputFromScreen = FALSE;
    BOOL bOutputToScreen = FALSE;
    BOOL bKeyFromScreen = FALSE;
    BOOL bOutputKeyToFile = FALSE;
    BOOL bKeyFromFile = FALSE;
    BOOL bEncrypt = FALSE;
    BOOL bDecrypt = FALSE;
    INT iKeyLen = 0;
    errno_t iError = 0;

    LPTSTR lptInputFile = NULL;
    LPTSTR lptOutputFile = NULL;
    LPTSTR lptKeyOutputFile = NULL;
    LPTSTR lptKeyInputFile = NULL;

    PBYTE pbKey = NULL;
    PBYTE pbInputData = NULL;
    PBYTE pbOutputData = NULL;

    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbCipherText = 0, cbPlainText = 0, cbData = 0, cbKeyObject = 0, cbBlockLen = 0, cbBlob = 0;
    PBYTE pbCipherText = NULL, pbPlainText = NULL, pbKeyObject = NULL, pbIV = NULL, pbIV2 = NULL, pbBlob = NULL;
    BCRYPT_ALG_HANDLE hRngAlgorithm = NULL;

    for (int i = 0; i < argc; i++) {
        if (_tcscmp(argv[i], TEXT("-i")) == 0) {
            if (i + 1 != argc) {
                bInputFromFile = TRUE;
                lptInputFile = argv[i + 1];
            }
        }
        if (_tcscmp(argv[i], TEXT("-iS")) == 0) {
            if (i + 1 != argc) {
                bInputFromScreen = TRUE;
                pbInputData = (BYTE*)argv[i + 1];
            }
        }
        if (_tcscmp(argv[i], TEXT("-o")) == 0) {
            bOutputToFile = TRUE;
            if (i + 1 != argc)
                lptOutputFile = argv[i + 1];
        }
        if (_tcscmp(argv[i], TEXT("-oS")) == 0) {
            if (i + 1 != argc) {
                bOutputToScreen = TRUE;
            }
        }
        if (_tcscmp(argv[i], TEXT("-kS")) == 0) {
            if (i + 1 != argc) {
                bKeyFromScreen = TRUE;
                iKeyLen = _tcslen(argv[i + 1]);
                pbKey = WideCharToPByte(argv[i + 1]);
            }
        }
        if (_tcscmp(argv[i], TEXT("-kG")) == 0) {
            if (i + 1 != argc) {
                bKeyGenerate = TRUE;
            }
        }
        if (_tcscmp(argv[i], TEXT("-k")) == 0) {
            if (i + 1 != argc) {
                bKeyFromFile = TRUE;
                lptKeyInputFile = argv[i + 1];
            }
        }
        if (_tcscmp(argv[i], TEXT("-oK")) == 0) {
            bOutputKeyToFile = TRUE;
            if (i + 1 != argc)
                lptKeyOutputFile = argv[i + 1];
        }
        if (_tcscmp(argv[i], TEXT("-e")) == 0)
            bEncrypt = TRUE;
        if (_tcscmp(argv[i], TEXT("-d")) == 0)
            bDecrypt = TRUE;
    }

    if(bInputFromFile && !bInputFromScreen && lptInputFile) {
        pbInputData = ReadFileData(lptInputFile);
    }

    if (pbInputData == NULL) {
        _tprintf(TEXT("[-] '-i' or '-iS' missing from the command line argument!\n[+] Exiting!\n"));
        goto Cleanup;
    }

    if (!bOutputToScreen && !bOutputToFile) {
        lptOutputFile = static_cast<LPTSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 10 * sizeof(TCHAR)));
        if (!lptOutputFile) {
            printf("[-] Memory allocation failed for output filename buffer.\n");
            goto Cleanup;
        }
        if (bEncrypt)
            _tcscpy_s(lptOutputFile, 10, TEXT("encrypted.txt"));
        else
            _tcscpy_s(lptOutputFile, 10, TEXT("decrypted.txt"));

    }

    if (bKeyFromFile && lptKeyInputFile) {
        pbKey = ReadFileData(lptKeyInputFile);
        iKeyLen = strlen((char*)pbKey);
    }

    if ((bKeyFromScreen || bKeyFromFile) && iKeyLen != KEY_LEN) {
        _tprintf(TEXT("[-] Key's length should be %d characters.\n"), KEY_LEN);
        goto Cleanup;
    }

    if (bKeyGenerate && pbKey == NULL) {
        pbKey = GenerateRandomBytes(KEY_LEN);
    }

    if (bKeyGenerate || bOutputKeyToFile) {
        if (lptKeyOutputFile) WriteDataToFile(pbKey, lptKeyOutputFile);
        else WriteDataToFile(pbKey, (LPTSTR)TEXT("key.bin"));
    }

    if (pbKey == NULL) {
        _tprintf(TEXT("[+] '-kS' or '-kG' or '-k' missing from the command line argument!\n[+] Exiting!\n"));
        goto Cleanup;
    }

    PrintBytes(pbKey, KEY_LEN);

    return EXIT_SUCCESS;


    // Open an algorithm handle.
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if (!NT_SUCCESS(status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Calculate the block length for the IV.
    if (!NT_SUCCESS(status = BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //// Determine whether the cbBlockLen is not longer than the IV length.
    //if (cbBlockLen > sizeof(rgbIV))
    //{
    //    wprintf(L"**** block length is longer than the provided IV length\n");
    //    goto Cleanup;
    //}

    //// Allocate a buffer for the IV. The buffer is consumed during the 
    //// encrypt/decrypt process.
    //pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
    //if (NULL == pbIV)
    //{
    //    wprintf(L"**** memory allocation failed\n");
    //    goto Cleanup;
    //}

    //memcpy(pbIV, rgbIV, cbBlockLen);
    
    // NEW CODE
    status = BCryptOpenAlgorithmProvider(
        &hRngAlgorithm,
        BCRYPT_RNG_ALGORITHM, // Use "RNG" as the algorithm identifier
        NULL,
        0
    );
    if (!NT_SUCCESS(status)) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, 32); // 16 bytes for IV
    if (NULL == pbIV) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    pbIV2 = (PBYTE)HeapAlloc(GetProcessHeap(), 0, 32); // 16 bytes for IV
    if (NULL == pbIV2) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    status = BCryptGenRandom(hRngAlgorithm, pbIV, 32, 0); // Generate IV bytes
    if (!NT_SUCCESS(status)) {
        wprintf(L"**** Error 0x%x returned by BCryptGenRandom\n", status);
        goto Cleanup;
    }
    // end NEW CODE

    printf("\nIV\n");
    PrintBytes(pbIV, 32);

    memcpy(pbIV2, pbIV, 32);
    printf("\nIV2\n");
    PrintBytes(pbIV2, 32);

    if (!NT_SUCCESS(status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        goto Cleanup;
    }

    // Generate the key from supplied input key bytes.
    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)rgbAES128Key, sizeof(rgbAES128Key), 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        goto Cleanup;
    }

    // get the size to allocate the buffer for save the key for later use
    if (!NT_SUCCESS(status = BCryptExportKey(hKey, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 0, &cbBlob, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }

    // Allocate the buffer to hold the BLOB.
    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    if (NULL == pbBlob)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }
    // Save another copy of the key for later.
    if (!NT_SUCCESS(status = BCryptExportKey(hKey, NULL, BCRYPT_KEY_DATA_BLOB, pbBlob, cbBlob, &cbBlob, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }


    cbPlainText = sizeof(rgbPlaintext);
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbPlainText, rgbPlaintext, sizeof(rgbPlaintext));

    //
    // Get the output buffer size.
    //
    if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, cbBlockLen, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (NULL == pbCipherText)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, cbBlockLen, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    printf("\nPlain\n");
    PrintBytes(pbPlainText, cbPlainText);

    printf("\nEncrypted\n");
    PrintBytes(pbCipherText, cbCipherText);

    // Destroy the key and reimport from saved BLOB.
    if (!NT_SUCCESS(status = BCryptDestroyKey(hKey)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDestroyKey\n", status);
        goto Cleanup;
    }
    hKey = 0;

    if (pbPlainText)
    {
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    }

    pbPlainText = NULL;

    // We can reuse the key object.
    memset(pbKeyObject, 0, cbKeyObject);


    // Reinitialize the IV because encryption would have modified it.
    // memcpy(pbIV, rgbIV, cbBlockLen);
    memcpy(pbIV, pbIV2, 32);

    if (!NT_SUCCESS(status = BCryptImportKey(hAesAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, pbKeyObject, cbKeyObject, pbBlob, cbBlob, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        goto Cleanup;
    }

    //
    // Get the output buffer size.
    //
    if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbBlockLen, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        goto Cleanup;
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbBlockLen, pbPlainText, cbPlainText, &cbPlainText, BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        goto Cleanup;
    }

    printf("\nDecrypted\n");
    PrintBytes(pbPlainText, cbPlainText);

    if (0 != memcmp(pbPlainText, (PBYTE)rgbPlaintext, sizeof(rgbPlaintext)))
    {
        wprintf(L"Expected decrypted text comparison failed.\n");
        goto Cleanup;
    }

    wprintf(L"Success!\n");


Cleanup:

    if (hAesAlg)
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    if (hKey)
        BCryptDestroyKey(hKey);
    if (pbCipherText)
        HeapFree(GetProcessHeap(), 0, pbCipherText);
    if (pbPlainText)
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbIV)
        HeapFree(GetProcessHeap(), 0, pbIV);
    if (pbInputData && bInputFromFile)
        HeapFree(GetProcessHeap(), 0, pbInputData);
    if (bKeyGenerate && pbKey)
        HeapFree(GetProcessHeap(), 0, pbKey);

    /*if (pbOutputData)
        HeapFree(GetProcessHeap(), 0, pbOutputData);*/
}