# CPP-Library

A C++ authentication library for secure user authentication, license validation, and user registration.

## Overview

CPP-Library is a comprehensive authentication solution that provides:
- User authentication with username/password
- License-based authentication with hardware ID validation
- User registration functionality
- Hardware ID generation for device identification
- Cross-platform C++ library

## Features

### Core Authentication Functions
- **User Login**: Authenticate users with username and password
- **License Validation**: Verify licenses against hardware IDs
- **User Registration**: Register new users with license validation
- **App Verification**: Validate application credentials
- **Input Validation**: Secure input validation for usernames and passwords
- **Hardware ID Generation**: Generate unique hardware identifiers

### Interface Functions
- **Interactive Login Interface**: Built-in UI for user authentication
- **Interactive License Interface**: Built-in UI for license validation
- **Interactive Registration Interface**: Built-in UI for user registration

## Project Structure

```
CPP-Library/
├── AuthManager.h           # Header file with function declarations
├── CPP-Library.cpp         # Main library implementation
├── framework.h             # Framework definitions
└── pch.h/pch.cpp          # Precompiled headers
```

## Building the Library

### Prerequisites
- Visual Studio 2019 or later
- Windows SDK

### Compilation

**Build the C++ Library**:
   ```bash
   msbuild CPP-Library.vcxproj /p:Configuration=Release /p:Platform=x64
   ```

## Usage

### C++ Library Functions

```cpp
// Configuration
void AuthManager_SetConfig(const char* appName, const char* ownerId, const char* appSecret);

// Core Functions
bool AuthManager_CheckAppExists(const char* appName, const char* ownerId, const char* appSecret);
bool AuthManager_CheckUserExists(const char* username, const char* password, const char* ownerId);
bool AuthManager_CheckLicense(const char* license, const char* hwid, const char* ownerId);
bool AuthManager_RegisterUser(const char* username, const char* password, const char* license, const char* hwid, const char* ownerId);

// Utility Functions
bool AuthManager_ValidateInput(const char* username, const char* password);
const char* AuthManager_GetHWID();

// Interface Functions
bool AuthManager_LoginInterface();
bool AuthManager_LicenseInterface();
bool AuthManager_RegisterInterface();
```

## Configuration

The library requires configuration with:
- **App Name**: Your application identifier
- **Owner ID**: Your unique owner identifier
- **App Secret**: Your application secret key

Server connection is hardcoded to `127.0.0.1:8080` for security.

## Security Features

- Hardware ID-based license validation
- Secure input validation
- Encrypted communication with authentication server
- Protection against common authentication vulnerabilities

## API Server

The library communicates with an authentication server running on `localhost:8080`. Ensure your authentication server is running and properly configured.

## License

See the [LICENSE](LICENSE) file for more details.

## Contributing

Contributions are welcome! Please ensure all changes maintain backward compatibility and include appropriate tests.

## Support

For issues and questions, please refer to the project documentation or create an issue in the project repository.