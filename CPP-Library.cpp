#include "pch.h"
#include "framework.h"
#include "AuthManager.h"
#include <string>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <vector>
#include <iostream>
#include <sstream>
#include <regex>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wbemuuid.lib")

using namespace std;

static string g_app_name = "";
static string g_ownerid = "";
static string g_app_secret = "";
static string g_server_host = "127.0.0.1";
static int g_server_port = 8080;
static string g_hwid_cache = "";
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

static int SendHttpPost(const string& host, int port, const string& path, const string& jsonData) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return -1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(host.c_str());

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    ostringstream request;
    request << "POST " << path << " HTTP/1.1\r\n";
    request << "Host: " << host << ":" << port << "\r\n";
    request << "Content-Type: application/json\r\n";
    request << "Content-Length: " << jsonData.length() << "\r\n";
    request << "Connection: close\r\n";
    request << "\r\n";
    request << jsonData;

    string requestStr = request.str();
    send(sock, requestStr.c_str(), requestStr.length(), 0);

    char buffer[1024];
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    buffer[bytesReceived] = '\0';

    closesocket(sock);
    WSACleanup();

    string response(buffer);
    size_t statusPos = response.find(" ");
    if (statusPos != string::npos) {
        string statusCode = response.substr(statusPos + 1, 3);
        return stoi(statusCode);
    }

    return -1;
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
void AuthManager_SetConfig(const char* appName, const char* ownerId, const char* appSecret, const char* serverHost, int serverPort) {
    g_app_name = appName ? appName : "";
    g_ownerid = ownerId ? ownerId : "";
    g_app_secret = appSecret ? appSecret : "";
    g_server_host = serverHost ? serverHost : "127.0.0.1";
    g_server_port = serverPort;
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
    int statusCode = SendHttpPost(g_server_host, g_server_port, "/auth/initiate", jsonData);
    
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
    int statusCode = SendHttpPost(g_server_host, g_server_port, "/auth/login", jsonData);
    
    return statusCode == 204; // NoContent
}

bool AuthManager_CheckLicense(const char* license, const char* hwid, const char* ownerId) {
    vector<pair<string, string>> data = {
        {"license", license ? license : ""},
        {"hwid", hwid ? hwid : ""},
        {"ownerId", ownerId ? ownerId : g_ownerid}
    };
    
    string jsonData = CreateJsonString(data);
    int statusCode = SendHttpPost(g_server_host, g_server_port, "/auth/login", jsonData);
    
    return statusCode == 204; // NoContent
}

bool AuthManager_RegisterUser(const char* email, const char* username, const char* password, const char* license, const char* hwid, const char* ownerId) {
    vector<pair<string, string>> data = {
        {"email", email ? email : ""},
        {"username", username ? username : ""},
        {"password", password ? password : ""},
        {"license", license ? license : ""},
        {"hwid", hwid ? hwid : ""},
        {"ownerId", ownerId ? ownerId : g_ownerid}
    };
    
    string jsonData = CreateJsonString(data);
    int statusCode = SendHttpPost(g_server_host, g_server_port, "/auth/register", jsonData);
    
    return statusCode == 204; // NoContent
}

// Utility functions
bool AuthManager_ValidateInput(const char* email, const char* username, const char* password) {
    if (!email || !username || !password) return false;
    
    string emailStr(email);
    string usernameStr(username);
    string passwordStr(password);
    
    regex usernameRegex("^[a-zA-Z][a-zA-Z0-9_-]{2,15}$");
    regex emailRegex("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$");
    regex passwordRegex("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$");

    return regex_match(usernameStr, usernameRegex) && 
           regex_match(emailStr, emailRegex) && 
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
    string email, username, password, license;
    cout << "Enter Email: ";
    cin >> email;
    cout << "Enter Username: ";
    cin >> username;
    cout << "Enter Password: ";
    cin >> password;
    cout << "Enter License: ";
    cin >> license;

    if (!AuthManager_ValidateInput(email.c_str(), username.c_str(), password.c_str())) {
        cout << "Invalid input. Please check your email, username, and password and try again." << endl;
        return false;
    }

    string hwid = GetHWIDInternal();

    bool registrationSuccess = AuthManager_RegisterUser(email.c_str(), username.c_str(), password.c_str(), license.c_str(), hwid.c_str(), g_ownerid.c_str());

    return registrationSuccess;
}