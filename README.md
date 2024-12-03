# File Encryption Tool 

A secure file encryption program built in C using OpenSSL's AES-256-GCM encryption. This tool provides military-grade encryption to protect your sensitive files.

##  Features

- **Strong Encryption**: Uses AES-256-GCM, one of the most secure encryption algorithms available
- **Salt Generation**: Unique random salt for each encryption
- **Secure Key Derivation**: PBKDF2 with 10,000 iterations for password-based key generation
- **Memory Security**: Secure memory wiping after use
- **Error Handling**: Comprehensive error checking and reporting

##  Prerequisites

Before you can build and run this program, you'll need:

- GCC compiler
- OpenSSL development libraries
- Make (optional, but recommended)

On Ubuntu/Debian, you can install these with:
```bash
sudo apt-get install gcc libssl-dev make
```

On macOS with Homebrew:
```bash
brew install openssl
```

##  Building the Program

1. Clone the repository:
```bash
git clone https://github.com/your-username/file-encryption.git
cd file-encryption
```

2. Compile the program:
```bash
gcc -o encrypt_file main.c -lssl -lcrypto
```

Or if you're using the Makefile:
```bash
make
```

## 🔧 How to Use

The basic syntax is:
```bash
./encrypt_file <input_file> <output_file> <password>
```

Example:
```bash
./encrypt_file secret.txt secret.enc mypassword123
```

##  Important Security Notes

1. Choose a strong password! The security of your encrypted files depends on it
2. Keep your password safe - there's no way to recover encrypted files without it
3. The program automatically generates a unique salt for each encryption
4. Make sure to keep track of your encrypted files and their corresponding passwords

##  Technical Details

- **Encryption Algorithm**: AES-256-GCM
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 10,000 iterations
- **Salt Length**: 32 bytes
- **Key Length**: 32 bytes
- **IV Length**: 16 bytes
- **Buffer Size**: 4096 bytes






