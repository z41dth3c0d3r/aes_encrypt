# Simple program written in c++ using WinAPI to encrypt and decrypt data using AES encryption algorith,

## Compilation

Used Visual Studio 2022 to develop this program.
Make sure to add `Bcrypt.lib` to Additional Dependencies under project Properties -> Linker -> Input.

and finally compile the program into x64 binary.

## Usage

```bash
Options
-------
         -i [path_to_file]        : Input data from a file.
         -iS [input_data]         : Input data from command line.
         -o [output_file_name]    : Output file name. default output filename "encrypted.bin" or "decrypted.bin" based on operation specified.
         -e                       : To encrypt the input data. random key will be generated and will get written to "key.bin" or file mentioned with "-oK".
         -d                       : To decrypt the input data. decryption key file should be specified with "-dK".
         -oK                      : Output key file name. to store the randomly generated key for encryption.
         -dK                      : Decryption key file name. should be exist for decryption.
         -kL                      : Key length for randomly generating key for encryption. should be 128 or 192 or 256 ONLY.
```

### Examples

Encrypt the text "Hello, World!" and write into file `hello.bin`

```bash
AESEncrypt.exe -iS "Hello, World!" -o hello.bin -e
```

output will be

```bash
[+] Written bytes to file "key.bin": 28 bytes.
[+] Written size and actual size match.
[+] Successfully writen the data to file.
[+] Written bytes to file "hello.bin": 32 bytes.
[+] Written size and actual size match.
[+] Successfully writen the data to file.
```

Decrypt the output file `hello.bin` into original text and write into file `hello.txt`

```bash
AESEncrypt.exe -i hello.bin -o hello.txt -dK key.bin -d
```

here i am also mentioning the keyfile which is written by encryption command!

output will be

```bash
[+] Opened the file "hello.bin" successfully.
[+] Size of the file : 32 bytes.
[+] Read bytes from the input file : 32 bytes.
[+] Opened the file "key.bin" successfully.
[+] Size of the file : 28 bytes.
[+] Read bytes from the input file : 28 bytes.
[+] Written bytes to file "hello.txt": 13 bytes.
[+] Written size and actual size match.
[+] Successfully writen the data to file.
```

if you want to use 128 bit key(default) or 192 bit key or 258 bit key than specify using `-kL` flag with `-e` flag for encryption.

for example:

```bash
AESEncrypt.exe -iS "Hello, World!" -o hello.bin -e -kL 256 -oK mykeyfile.bin
```

here i am also mentioning the output key file!

### Enjoy!
