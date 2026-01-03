# CLAUDE.md - Cryptography Module

## Module Overview

The Cryptography module provides comprehensive cryptographic functionality for the Malterlib framework, built on top of Google's BoringSSL library. This module is a fundamental dependency for the Network module and other security-sensitive components.

## Key Components

### Core Cryptographic Functions
- **Hash Functions**: MD5, SHA family (SHA1, SHA256, SHA384, SHA512)
- **Symmetric Cryptography**: AES encryption/decryption with various modes
- **Public Key Cryptography**: RSA, Elliptic Curve (secp256r1, secp384r1, secp521r1, X25519)
- **Message Authentication**: HMAC implementations
- **Key Derivation**: PBKDF2 and other key derivation functions
- **Random Data Generation**: Cryptographically secure random number generation
- **UUID Generation**: Version 4 UUID generation
- **Certificate Management**: X.509 certificate generation, validation, and system integration

### Special Components
- **EncryptedStream**: Stream-based encryption/decryption for large data
- **RandomID**: Unique identifier generation with configurable entropy
- **MD5Cache**: Optimized MD5 caching for performance-critical applications

## Module-Specific Conventions

### Namespace Organization
- Primary namespace: `NMib::NCryptography`
- BoringSSL integration: `NMib::NCryptography::NBoringSSL`

### Naming Patterns
- Hash classes: `CHash_[Algorithm]` (e.g., `CHash_MD5`, `CHash_SHA256`)
- Template classes: `TC[Component]` (e.g., `TCHashImpl`, `TCMessageDigest`)
- Public key settings: `CPublicKeySettings_[Type]` (e.g., `CPublicKeySettings_RSA`)
- Constants: `mc_[Name]` (e.g., `mc_DigestSize`)

### Memory Management
- Uses Malterlib's memory allocation system
- Secure memory wiping for sensitive data
- RAII patterns for cryptographic contexts

### Error Handling
- Custom exception types via `Malterlib_Cryptography_Exception.h`
- BoringSSL error code integration
- Certificate validation error reporting

## Dependencies

### External
- **BoringSSL**: Google's fork of OpenSSL (main cryptographic backend)
  - Located in `../../External/boringssl/`
  - Includes: crypto, ssl, decrepit, fipsmodule libraries
  - Custom build configuration via CMake import

### Internal Malterlib Modules
- **Core**: Basic types and platform abstractions
- **Memory**: Memory management
- **Stream**: Stream interfaces for encrypted streams
- **String**: String handling utilities
- **Exception**: Exception framework

### Platform-Specific
- Windows: Custom assembly optimizations (`Malterlib_Cryptography_BoringSSL_Windows_x64.asm`)
- macOS: Security framework integration for certificate management
- Linux: System certificate store integration

## Common Tasks

### Adding New Hash Algorithm
1. Create new files: `Malterlib_Cryptography_Hash_[Name].h/cpp`
2. Implement using `TCHashImpl_BoringSSL` template
3. Add to `Malterlib_Cryptography_Hash.h` includes
4. Create test in `Test/Test_Malterlib_Cryptography_Digest.cpp`

### Working with Certificates
```cpp
// Certificate generation and validation handled via
// Malterlib_Cryptography_Certificate.h
// System integration in Malterlib_Cryptography_Certificate_System.cpp
```

### Using Symmetric Encryption
```cpp
// AES encryption via Malterlib_Cryptography_SymmetricCrypto.h
// Stream-based encryption via Malterlib_Cryptography_EncryptedStream.h
```

### Running Module Tests
```bash
# Build tests
MalterlibBuildShowProgress=false ./mib build Tests macOS arm64 Debug

# Run all cryptography tests
/opt/Deploy/Tests/RunAllTests --paths '["Cryptography/*"]'

# Run specific test
/opt/Deploy/Tests/RunAllTests --paths '["Cryptography/Certificate"]'
```

## Important Files

### Headers (Public API)
- `Include/Mib/Cryptography/*` - Public headers for external use
- `Source/Malterlib_Cryptography_*.h` - Implementation headers

### Core Implementation
- `Malterlib_Cryptography_BoringSSL.cpp/h` - BoringSSL integration and initialization
- `Malterlib_Cryptography_Certificate.cpp/h` - Certificate management
- `Malterlib_Cryptography_SymmetricCrypto.cpp/h` - Symmetric encryption
- `Malterlib_Cryptography_PublicCrypto.cpp/h` - Public key operations

### Build Configuration
- `Malterlib_Cryptography.MHeader` - Module build configuration
- BoringSSL import and compilation settings
- Dependency injection groups for linking

## Module-Specific Notes

### Security Considerations
- All cryptographic operations use BoringSSL's FIPS-compliant implementations
- Memory containing keys and sensitive data is securely wiped after use
- Random number generation uses OS-provided secure random sources
- Certificate validation includes full chain verification

### Performance Optimizations
- MD5Cache for repeated hash operations
- Assembly optimizations on Windows x64
- Streaming interfaces to avoid large memory allocations
- Template-based implementations for compile-time optimization

### Platform Differences
- **Windows**: Uses CryptoAPI for system certificate store
- **macOS**: Uses Security framework for keychain integration
- **Linux**: Uses OpenSSL-compatible certificate paths
- **Assembly**: Platform-specific optimizations (currently Windows x64 only)

### Known Limitations
- BoringSSL is statically linked (no dynamic loading)
- FIPS mode configuration is compile-time only
- Some elliptic curves not available on all platforms
- Certificate generation limited to X.509v3

### Build System Integration
- LinkerGroup "BoringSSL" ensures proper library linking order
- CMake variables configured for BoringSSL discovery
- Automatic dependency injection for targets using cryptography
- Special handling for assembly files on Windows

### Testing Guidelines
- Always test on all target platforms due to platform-specific code
- Verify certificate operations with system certificate stores
- Test streaming encryption with large files (>1GB)
- Validate random data generation statistical properties
- Check for memory leaks in cryptographic operations
