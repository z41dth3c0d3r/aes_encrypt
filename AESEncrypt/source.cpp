#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <tchar.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define BLOCK_LEN 16


void PrintBytes(IN BYTE* pbPrintData, IN DWORD cbDataLen)
{
    DWORD dwCount = 0;

    for (dwCount = 0; dwCount < cbDataLen;dwCount++)
    {
        printf("0x%02x, ", pbPrintData[dwCount]);

        if (0 == (dwCount + 1) % 10) putchar('\n');
    }
}

PBYTE ReadFileData(LPTSTR lptFileName, DWORD *pcbReadSize) {
    HANDLE hFile;
    PBYTE pbFileData = NULL;

    hFile = CreateFile(lptFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error opening the input file. %d \n", GetLastError());
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

    *pcbReadSize = bytesRead;

    return pbFileData;
}

BOOL WriteDataToFile(PBYTE pbData, DWORD cbData, LPTSTR lptWriteFileName) {
    HANDLE hFile = CreateFile(lptWriteFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("[-] Unable to create or open file  \"%s\" for write.\n"), lptWriteFileName);
        return FALSE;
    }

    DWORD cbBytesWritten = 0;

    if (!WriteFile(
        hFile,
        pbData,
        cbData,
        &cbBytesWritten,
        NULL
    )) {
        CloseHandle(hFile);
        return FALSE;
    }

    _tprintf(TEXT("[+] Written bytes to file \"%s\": %d bytes.\n"), lptWriteFileName, cbBytesWritten);

    if (cbBytesWritten != cbData)
        printf("[-] Written size and actual size doesn't match.\n");
    else
        printf("[+] Written size and actual size match.\n");

    CloseHandle(hFile);

    printf("[+] Successfully writen the data to file.\n");


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
    printf("\nUsage : AESEncrypt.exe [options]\n\n");
    printf("Options\n");
    printf("-------\n");
    printf("\t -i [path_to_file]        : Input data from a file.\n");
    printf("\t -iS [input_data]         : Input data from command line.\n");
    printf("\t -o [output_file_name]    : Output file name. default output filename \"encrypted.bin\" or \"decrypted.bin\" based on operation specified.\n");
    printf("\t -e                       : To encrypt the input data. random key will be generated and will get written to \"key.bin\" or file mentioned with \"-oK\".\n");
    printf("\t -d                       : To decrypt the input data. decryption key file should be specified with \"-dK\".\n");
    printf("\t -oK                      : Output key file name. to store the randomly generated key for encryption.\n");
    printf("\t -dK                      : Decryption key file name. should be exist for decryption.\n");
    printf("\t -kL                      : Key length for randomly generating key for encryption. should be 128 or 192 or 256 ONLY.\n");
}

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

NTSTATUS GenerateSymmetricKey(BCRYPT_ALG_HANDLE hAesAlg, BCRYPT_KEY_HANDLE *phKey, DWORD dwKeyLen, PBYTE* ppbBlob, DWORD *pcbBlob) {

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbBlob = 0;
    PBYTE pbBlob = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PBYTE pbAesKeyMeterial = NULL;
    
    pbAesKeyMeterial = GenerateRandomBytes(dwKeyLen);
    if (pbAesKeyMeterial == NULL) {
        _tprintf(TEXT("[-] Error on generating random bytes\n"));
        return status;
    }
    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, pbAesKeyMeterial, dwKeyLen, 0)))
    {
        _tprintf(TEXT("[-] Error 0x%x returned by BCryptGenerateSymmetricKey\n"), status);
        HeapFree(GetProcessHeap(), 0, pbAesKeyMeterial);
        return status;
    }

    // get the size to allocate the buffer for save the key for later use
    if (!NT_SUCCESS(status = BCryptExportKey(hKey, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 0, &cbBlob, 0)))
    {
        _tprintf(TEXT("[-] Error 0x%x returned by BCryptExportKey\n"), status);
        HeapFree(GetProcessHeap(), 0, pbAesKeyMeterial);
        return status;
    }

    // Allocate the buffer to hold the BLOB.
    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    if (NULL == pbBlob)
    {
        _tprintf(TEXT("[-] memory allocation failed\n"));
        HeapFree(GetProcessHeap(), 0, pbAesKeyMeterial);
        return status;
    }
    // Save another copy of the key for later.
    if (!NT_SUCCESS(status = BCryptExportKey(hKey, NULL, BCRYPT_KEY_DATA_BLOB, pbBlob, cbBlob, &cbBlob, 0)))
    {
        _tprintf(TEXT("[-] Error 0x%x returned by BCryptExportKey\n"), status);
        HeapFree(GetProcessHeap(), 0, pbAesKeyMeterial);
        HeapFree(GetProcessHeap(), 0, pbBlob);
        return status;
    }

    HeapFree(GetProcessHeap(), 0, pbAesKeyMeterial);

    *pcbBlob = cbBlob;
    *ppbBlob = pbBlob;
    *phKey = hKey;

    return 0;
}

NTSTATUS Encrypt(BCRYPT_KEY_HANDLE hKey, PBYTE pbPlainText, DWORD cbPlainText, PBYTE *ppbEncryptedData, DWORD *pcbEncryptedData) {

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbData = 0, cbCipherText = 0;
    PBYTE pbIV = NULL, pbCipherText = NULL, pbCipherTextAndIV = NULL;

    pbIV = GenerateRandomBytes(BLOCK_LEN);

    if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, BLOCK_LEN, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING)))
    {
        _tprintf(TEXT("[-] Error 0x%x returned by BCryptEncrypt\n"), status);
        HeapFree(GetProcessHeap(), 0, pbIV);
        return status;
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (NULL == pbCipherText)
    {
        _tprintf(TEXT("[-] memory allocation failed\n"));
        HeapFree(GetProcessHeap(), 0, pbIV);
        return STATUS_UNSUCCESSFUL;
    }

    pbCipherTextAndIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText + BLOCK_LEN + 1);
    if (NULL == pbCipherTextAndIV)
    {
        _tprintf(TEXT("[-] memory allocation failed\n"));
        HeapFree(GetProcessHeap(), 0, pbIV);
        HeapFree(GetProcessHeap(), 0, pbCipherText);
        return STATUS_UNSUCCESSFUL;
    }
    memcpy(pbCipherTextAndIV, pbIV, BLOCK_LEN);

    if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, BLOCK_LEN, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING)))
    {
        _tprintf(TEXT("[-] Error 0x%x returned by BCryptEncrypt\n"), status);
        HeapFree(GetProcessHeap(), 0, pbIV);
        HeapFree(GetProcessHeap(), 0, pbCipherText);
        HeapFree(GetProcessHeap(), 0, pbCipherTextAndIV);
        return STATUS_UNSUCCESSFUL;
    }

    memcpy(pbCipherTextAndIV + BLOCK_LEN, pbCipherText, cbCipherText);
    pbCipherTextAndIV[cbCipherText + BLOCK_LEN] = '\0';

    HeapFree(GetProcessHeap(), 0, pbCipherText);
    HeapFree(GetProcessHeap(), 0, pbIV);

    *ppbEncryptedData = pbCipherTextAndIV;
    *pcbEncryptedData = cbCipherText + BLOCK_LEN;

    return 0;
}

NTSTATUS Decrypt(BCRYPT_KEY_HANDLE hKey, PBYTE pbCipherTextAndIV, DWORD cbCipherTextAndIV, PBYTE* ppbPlainText, DWORD* pcbPlainText) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbData = 0, cbPlainText = 0, cbCipherText = 0;
    PBYTE pbIV = NULL, pbCipherText = NULL, pbPlainText = NULL;

    cbCipherText = cbCipherTextAndIV - BLOCK_LEN;

    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, BLOCK_LEN);

    if (NULL == pbIV)
    {
        _tprintf(TEXT("[-] memory allocation failed\n"));
        return STATUS_UNSUCCESSFUL;
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);

    if (NULL == pbCipherText)
    {
        _tprintf(TEXT("[-] memory allocation failed\n"));
        return STATUS_UNSUCCESSFUL;
    }

    memcpy(pbIV, pbCipherTextAndIV, BLOCK_LEN);
    memcpy(pbCipherText, pbCipherTextAndIV + BLOCK_LEN, cbCipherText);

    if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, BLOCK_LEN, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING)))
    {
        _tprintf(TEXT("[-] Error 0x%x returned by BCryptDecrypt\n"), status);
        return status;
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        _tprintf(TEXT("[-] memory allocation failed\n"));
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, BLOCK_LEN, pbPlainText, cbPlainText, &cbPlainText, BCRYPT_BLOCK_PADDING)))
    {
        _tprintf(TEXT("[-] Error 0x%x returned by BCryptDecrypt\n"), status);
        return status;
    }

    HeapFree(GetProcessHeap(), 0, pbIV);
    HeapFree(GetProcessHeap(), 0, pbCipherText);

    *ppbPlainText = pbPlainText;
    *pcbPlainText = cbPlainText;

    return 0;
}

int _tmain(int argc, TCHAR *argv[])
{
    if (argc < 4 || argc > 10) {
        PrintUsage();
        return EXIT_SUCCESS;
    }

    BOOL bInputFromFile = FALSE, bOutputToFile = FALSE, bInputFromScreen = FALSE, bOutputKeyToFile = FALSE, bEncrypt = FALSE, bDecrypt = FALSE, bKeyLenProvided = FALSE;

    LPTSTR lptInputFile = NULL, lptOutputFile = NULL, lptKeyOutputFile = NULL, lptDecryptionKeyFile = NULL;

    BCRYPT_ALG_HANDLE hAesAlg = NULL;

    BCRYPT_KEY_HANDLE hKey = NULL;

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    DWORD cbCipherText = 0, cbPlainText = 0, cbData = 0, cbBlockLen = 0, cbBlob = 0, cbCipherTextAndIV = 0, cbKey = 0, cbInputData = 0, dwKeyLen = 0;

    PBYTE pbPlainText = NULL, pbBlob = NULL, pbCipherTextAndIV = NULL, pbInputData = NULL;

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
                pbInputData = WideCharToPByte(argv[i + 1]);
                cbInputData = _tcslen(argv[i + 1]);
            }
        }
        if (_tcscmp(argv[i], TEXT("-o")) == 0) {
            bOutputToFile = TRUE;
            if (i + 1 != argc)
                lptOutputFile = argv[i + 1];
        }
        if (_tcscmp(argv[i], TEXT("-dK")) == 0) {
            if (i + 1 != argc) {
                lptDecryptionKeyFile = argv[i + 1];
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
        if (_tcscmp(argv[i], TEXT("-kL")) == 0) {
            bKeyLenProvided = TRUE;
            if (i + 1 != argc)
                dwKeyLen = wcstoul(argv[i + 1], NULL, 10);
        }
    }

    if (bInputFromFile && !bInputFromScreen && lptInputFile) {
        pbInputData = ReadFileData(lptInputFile, &cbInputData);
    }

    if (pbInputData == NULL) {
        _tprintf(TEXT("[-] '-i' or '-iS' missing from the command line argument!\n[+] Exiting!\n"));
        goto Cleanup;
    }

    if (!bEncrypt && !bDecrypt) {
        _tprintf(TEXT("[-] '-d' or '-e' missing from the command line argument!\n[+] Exiting!\n"));
        goto Cleanup;
    }

    if (lptOutputFile == NULL) {
        if (bEncrypt)
            lptOutputFile = (LPTSTR)TEXT("encrypted.bin");
        else
            lptOutputFile = (LPTSTR)TEXT("decrypted.bin");
    }

    if (bDecrypt && !lptDecryptionKeyFile) {
        _tprintf(TEXT("[+] Decryption key file missing!\n[+] Exiting!\n"));
        goto Cleanup;
    }

    if (bKeyLenProvided) {
        if ((dwKeyLen != 128) && (dwKeyLen != 192) && (dwKeyLen != 256)) {
            _tprintf(TEXT("[-] -kL should be 128 or 192 or 256 bit\n"));
            goto Cleanup;
        }
    }
    else {
        dwKeyLen = 128;
    }

    dwKeyLen = dwKeyLen / 8;

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
    {
        _tprintf(TEXT("[-] Error 0x%x returned by BCryptOpenAlgorithmProvider\n"), status);
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
    {
        _tprintf(TEXT("[-] Error 0x%x returned by BCryptSetProperty\n"), status);
        goto Cleanup;
    }

    if (bEncrypt) {
        pbPlainText = pbInputData;
        cbPlainText = cbInputData;

        GenerateSymmetricKey(hAesAlg, &hKey, dwKeyLen, &pbBlob, &cbBlob);

        if (bOutputKeyToFile) {
            if (lptKeyOutputFile) WriteDataToFile(pbBlob, cbBlob, lptKeyOutputFile);
        }
        else WriteDataToFile(pbBlob, cbBlob, PByteToWideChar((BYTE*)"key.bin"));

        if (!NT_SUCCESS(status = Encrypt(hKey, pbPlainText, cbPlainText, &pbCipherTextAndIV, &cbCipherTextAndIV))) {
            _tprintf(TEXT("[-] Encrypt failed\n"));
            goto Cleanup;
        }

        WriteDataToFile(pbCipherTextAndIV, cbCipherTextAndIV, lptOutputFile);

        HeapFree(GetProcessHeap(), 0, pbCipherTextAndIV);
    }

    else if (bDecrypt) {
        pbCipherTextAndIV = pbInputData;
        cbCipherTextAndIV = cbInputData;

        if (lptDecryptionKeyFile) {
            pbBlob = ReadFileData(lptDecryptionKeyFile, &cbBlob);
        }

        if (pbBlob != NULL) {
            if (!NT_SUCCESS(status = BCryptImportKey(hAesAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0, pbBlob, cbBlob, 0)))
            {
                _tprintf(TEXT("[-] Error 0x%x returned by BCryptImportKey\n"), status);
                goto Cleanup;
            }

            if (!NT_SUCCESS(status = Decrypt(hKey, pbCipherTextAndIV, cbCipherTextAndIV, &pbPlainText, &cbPlainText)))
            {
                _tprintf(TEXT("[-] Error 0x%x returned by BCryptDecrypt\n"), status);
                goto Cleanup;
            }

            WriteDataToFile(pbPlainText, cbPlainText, lptOutputFile);

            HeapFree(GetProcessHeap(), 0, pbPlainText);
        }
        else {
            _tprintf(TEXT("[-] Key not found in the file.\n"));
            goto Cleanup;
        }
    }


Cleanup:

    if (hAesAlg)
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    if (hKey)
        BCryptDestroyKey(hKey);
    if (pbBlob)
        HeapFree(GetProcessHeap(), 0, pbBlob);
    if (bInputFromFile && pbInputData)
        HeapFree(GetProcessHeap(), 0, pbInputData);
}