#include "pch.h"
#include "framework.h"
#include "AuthManager.h"
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <regex>
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wbemuuid.lib")

using namespace std;

static string g_app_name = ""; // Leave it blank
static string g_ownerid = ""; // Leave it blank
static string g_app_secret = ""; // Leave it blank
static string g_server_host = "https://api.authmanager.xyz"; 
// static int g_server_port = 8080;
static string g_hwid_cache = ""; // Leave it blank
static bool g_initialized = false;

// Internal utility functions
static string CreateJsonString(const vector<pair<string, string>>& data) {
    ostringstream json;
    json << "{";
    for (size_t i = 0; i < data.size(); ++i) {
        json << "\"" << data[i].first << "\":\"" << data[i].second << "\"";
        if (i < data.size() - 1) json << ",";
    }
    json << "}";
    return json.str();
}

static int SendHttpPost(const string& url, const string& path, const string& jsonData) {
    bool isHttps = (url.find("https://") == 0);
    string host = url;
    if (isHttps) {
        host = host.substr(8); 
    } else if (host.find("http://") == 0) {
        host = host.substr(7); 
    }
    
    int hostLen = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, NULL, 0);
    wstring wHost(hostLen, 0);
    MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, &wHost[0], hostLen);
    
    int pathLen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, NULL, 0);
    wstring wPath(pathLen, 0);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wPath[0], pathLen);

    HINTERNET hSession = WinHttpOpen(L"AuthManager/1.0", 
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, 
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return -1;

    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), 
                                        isHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return -1;
    }

    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(),
                                            NULL, WINHTTP_NO_REFERER, 
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }

    wstring headers = L"Content-Type: application/json\r\n";
    WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                     (LPVOID)jsonData.c_str(), jsonData.length(), 
                                     jsonData.length(), 0);
    
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }

    result = WinHttpReceiveResponse(hRequest, NULL);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return (int)statusCode;
}

static string GetHWIDInternal() {
    if (!g_hwid_cache.empty()) {
        return g_hwid_cache;
    }
    
    DWORD serialNumber = 0;
    if (GetVolumeInformationA(
        "C:\\",            // Root directory to retrieve volume information
        nullptr,           // Volume name buffer
        0,                 // Volume name buffer size
        &serialNumber,     // Volume serial number
        nullptr,           // Maximum component length
        nullptr,           // File system flags
        nullptr,           // File system name buffer
        0                  // File system name buffer size
    )) {
        g_hwid_cache = to_string(serialNumber);
        return g_hwid_cache;
    }
    else {
        return "Error getting HWID";
    }
}

// Configuration function
void AuthManager_SetConfig(const char* appName, const char* ownerId, const char* appSecret, const char* serverHost, unsigned int serverPort) { // if local then removed unsigned
    g_app_name = appName ? appName : "";
    g_ownerid = ownerId ? ownerId : "";
    g_app_secret = appSecret ? appSecret : "";
    g_server_host = serverHost ? serverHost : "https://api.authmanager.xyz";
    // g_server_port = serverPort; // if local then remove those comments
}

// Core authentication functions
bool AuthManager_CheckAppExists(const char* appName, const char* ownerId, const char* appSecret) {
    if (!appName || !ownerId || !appSecret || 
        strlen(appName) == 0 || strlen(ownerId) == 0 || strlen(appSecret) == 0) {
        return false; // All parameters are required
    }
    
    // Set global variables for future use
    g_app_name = string(appName);
    g_ownerid = string(ownerId);
    g_app_secret = string(appSecret);
    
    vector<pair<string, string>> data = {
        {"name", g_app_name},
        {"ownerId", g_ownerid},
        {"secret", g_app_secret}
    };
    
    string jsonData = CreateJsonString(data);
    int statusCode = SendHttpPost(g_server_host, "/auth/initiate", jsonData); // if local then add g_server_port
    
    g_initialized = (statusCode == 204);
    return g_initialized;
}

bool AuthManager_CheckUserExists(const char* username, const char* password, const char* ownerId) {
    vector<pair<string, string>> data = {
        {"username", username ? username : ""},
        {"password", password ? password : ""},
        {"ownerId", ownerId ? ownerId : g_ownerid}
    };
    
    string jsonData = CreateJsonString(data);
    int statusCode = SendHttpPost(g_server_host, "/auth/login", jsonData); // if local then add g_server_port
    
    return statusCode == 204; // NoContent
}

bool AuthManager_CheckLicense(const char* license, const char* hwid, const char* ownerId) {
    vector<pair<string, string>> data = {
        {"license", license ? license : ""},
        {"hwid", hwid ? hwid : ""},
        {"ownerId", ownerId ? ownerId : g_ownerid}
    };
    
    string jsonData = CreateJsonString(data);
    int statusCode = SendHttpPost(g_server_host, "/auth/login", jsonData); // if local then add g_server_port
    
    return statusCode == 204; // NoContent
}

bool AuthManager_RegisterUser(const char* username, const char* password, const char* license, const char* hwid, const char* ownerId) {
    vector<pair<string, string>> data = {
        {"username", username ? username : ""},
        {"password", password ? password : ""},
        {"license", license ? license : ""},
        {"hwid", hwid ? hwid : ""},
        {"ownerId", ownerId ? ownerId : g_ownerid}
    };
    
    string jsonData = CreateJsonString(data);
    int statusCode = SendHttpPost(g_server_host, "/auth/register", jsonData); // if local then add g_server_port
    
    return statusCode == 204; // NoContent
}

// Utility functions
bool AuthManager_ValidateInput(const char* username, const char* password) {
    if (!username || !password) return false;
    
    string usernameStr(username);
    string passwordStr(password);
    
    regex usernameRegex("^[a-zA-Z][a-zA-Z0-9_-]{2,15}$");
    regex passwordRegex("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$");

    return regex_match(usernameStr, usernameRegex) && 
           regex_match(passwordStr, passwordRegex);
}

const char* AuthManager_GetHWID() {
    static string hwid = GetHWIDInternal();
    return hwid.c_str();
}

// Authentication interface
bool AuthManager_Login() {
    string username, password;
    cout << "Enter Username: ";
    cin >> username;
    cout << "Enter Password: ";
    cin >> password;

    bool userExists = AuthManager_CheckUserExists(username.c_str(), password.c_str(), g_ownerid.c_str());
    cout << (userExists ? "User exists." : "User doesn't exist.") << endl;

    return userExists;
}

bool AuthManager_License() {
    string license;
    cout << "Enter License: ";
    cin >> license;

    string hwid = GetHWIDInternal();

    bool licenseIsValid = AuthManager_CheckLicense(license.c_str(), hwid.c_str(), g_ownerid.c_str());
    cout << (licenseIsValid ? "License is valid." : "License is invalid.") << endl;

    return licenseIsValid;
}

bool AuthManager_Register() {
    string username, password, license;
    cout << "Enter Username: ";
    cin >> username;
    cout << "Enter Password: ";
    cin >> password;
    cout << "Enter License: ";
    cin >> license;

    if (!AuthManager_ValidateInput(username.c_str(), password.c_str())) {
        cout << "Invalid input. Please check your username and password and try again." << endl;
        return false;
    }

    string hwid = GetHWIDInternal();

    bool registrationSuccess = AuthManager_RegisterUser(username.c_str(), password.c_str(), license.c_str(), hwid.c_str(), g_ownerid.c_str());

    return registrationSuccess;
}