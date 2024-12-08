# File Encryption Tool 



##  Features

- **Strong Encryption**: Uses AES-256-GCM, one of the most secure encryption algorithms available
- **Salt Generation**: Unique random salt for each encryption
- **Secure Key Derivation**: PBKDF2 with 10,000 iterations for password-based key generation
- **Memory Security**: Secure memory wiping after use
- **Error Handling**: Comprehensive error checking and reporting

##  Prerequisites


- GCC compiler
- OpenSSL development libraries
- Make (optional, but recommended)


##  Technical Details

- **Encryption Algorithm**: AES-256-GCM
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 10,000 iterations
- **Salt Length**: 32 bytes
- **Key Length**: 32 bytes
- **IV Length**: 16 bytes
- **Buffer Size**: 4096 bytes






