#include <windows.h>
#include <objbase.h>
#include <sddl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include "filter_id.h"

namespace {
class Key {
    HKEY value_ = nullptr;
public:
    Key() = default;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    ~Key() { if (value_) RegCloseKey(value_); }
    HKEY get() const { return value_; }
    HKEY* put() { return &value_; }
    void close() { if (value_) RegCloseKey(value_); value_ = nullptr; }
};
void require(LSTATUS result, const char* operation) {
    if (result != ERROR_SUCCESS) throw std::runtime_error(std::string(operation) + " (Windows error " + std::to_string(result) + ")");
}
void check(bool condition, const char* operation) {
    if (!condition) throw std::runtime_error(operation);
    std::cout << "PASS " << operation << '\n';
}
std::wstring uniqueName() {
    GUID id{};
    if (FAILED(CoCreateGuid(&id))) throw std::runtime_error("Cannot create recovery identifier");
    wchar_t text[40]{};
    if (!StringFromGUID2(id, text, static_cast<int>(std::size(text)))) throw std::runtime_error("Cannot format recovery identifier");
    return text;
}
bool keyExists(HKEY parent, const wchar_t* path) {
    Key key;
    const auto result = RegOpenKeyExW(parent, path, 0, KEY_READ, key.put());
    if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) return false;
    require(result, "Inspect registry key");
    return true;
}
bool removeRegistration(HKEY software) {
    // Intentionally non-recursive. Unexpected children stop recovery instead of
    // extending its scope. The provider, COM class, PIN and profiles stay intact.
    const auto result = RegDeleteKeyW(software, SovereignFilterRegistration);
    if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) return false;
    require(result, "Remove only Sovereign filter registration");
    require(RegFlushKey(software), "Persist filter removal");
    return true;
}
void enablePrivilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        throw std::runtime_error("Cannot open recovery process token");
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid)) {
        CloseHandle(token);
        throw std::runtime_error("Cannot identify recovery privilege");
    }
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    const auto adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    const auto error = GetLastError();
    CloseHandle(token);
    if (!adjusted || error != ERROR_SUCCESS) throw std::runtime_error("Recovery requires backup and restore privileges in WinRE/WinPE");
}
std::wstring absoluteWindowsRoot(const wchar_t* argument) {
    // A local, explicit drive path avoids UNC targets and alternate-device syntax.
    const std::wstring input(argument);
    if (input.size() < 3 || !((input[0] >= L'A' && input[0] <= L'Z') || (input[0] >= L'a' && input[0] <= L'z')) ||
        input[1] != L':' || input[2] != L'\\' || input.find(L':', 2) != std::wstring::npos)
        throw std::runtime_error("Supply the offline Windows directory as a local absolute path, for example C:\\Windows");
    wchar_t absolute[32768]{};
    const auto count = GetFullPathNameW(argument, static_cast<DWORD>(std::size(absolute)), absolute, nullptr);
    if (!count || count >= std::size(absolute)) throw std::runtime_error("Invalid offline Windows path");
    std::wstring root(absolute);
    while (root.size() > 3 && root.back() == L'\\') root.pop_back();
    // Reject reparse points in the entire path, not only at its final component.
    for (size_t end = 3; end <= root.size(); ++end) {
        if (end != root.size() && root[end] != L'\\') continue;
        const auto part = root.substr(0, end);
        const auto attributes = GetFileAttributesW(part.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) throw std::runtime_error("Offline Windows path is missing or traverses a reparse point");
    }
    wchar_t running[32768]{};
    const auto runningCount = GetWindowsDirectoryW(running, static_cast<UINT>(std::size(running)));
    if (!runningCount || runningCount >= std::size(running)) throw std::runtime_error("Cannot identify the running recovery environment");
    // The recovery environment's own volume can never be the requested target.
    if (towupper(root[0]) == towupper(running[0])) throw std::runtime_error("Refusing the running Windows volume");
    return root;
}
void requireRegularFile(const std::wstring& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
        throw std::runtime_error("Required offline file is missing or is a reparse point");
}
void recover(const wchar_t* argument) {
    if (!keyExists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\MiniNT"))
        throw std::runtime_error("Offline recovery runs only from WinRE/WinPE. No live registry changes were made.");
    const auto root = absoluteWindowsRoot(argument);
    const auto config = root + L"\\System32\\config";
    // Include the remaining ancestor directories in the reparse-point check.
    (void)absoluteWindowsRoot(config.c_str());
    const auto hive = config + L"\\SOFTWARE";
    requireRegularFile(hive);
    requireRegularFile(root + L"\\System32\\ntoskrnl.exe");
    enablePrivilege(SE_BACKUP_NAME);
    enablePrivilege(SE_RESTORE_NAME);
    const auto unique = uniqueName();
    const auto backup = config + L"\\SovereignFilterRecovery-" + unique;
    PSECURITY_DESCRIPTOR security = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        SDDL_REVISION_1, &security, nullptr)) throw std::runtime_error("Cannot construct protected backup permissions");
    SECURITY_ATTRIBUTES backupAttributes{sizeof(SECURITY_ATTRIBUTES), security, FALSE};
    const auto created = CreateDirectoryW(backup.c_str(), &backupAttributes);
    LocalFree(security);
    if (!created) throw std::runtime_error("Cannot create a fresh protected recovery-backup directory");
    for (const auto suffix : {L"", L".LOG1", L".LOG2"}) {
        const auto source = hive + suffix;
        const auto attributes = GetFileAttributesW(source.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND && *suffix) continue;
        requireRegularFile(source);
        if (!CopyFileW(source.c_str(), (backup + L"\\SOFTWARE" + suffix).c_str(), TRUE))
            throw std::runtime_error("Registry backup failed; the original hive was not loaded or changed");
    }
    const auto mount = L"SovereignFilterRecovery-" + unique;
    if (keyExists(HKEY_LOCAL_MACHINE, mount.c_str())) throw std::runtime_error("Recovery mount already exists");
    require(RegLoadKeyW(HKEY_LOCAL_MACHINE, mount.c_str(), hive.c_str()), "Load offline SOFTWARE hive");
    bool removed = false;
    try {
        Key software;
        require(RegOpenKeyExW(HKEY_LOCAL_MACHINE, mount.c_str(), 0, KEY_ALL_ACCESS, software.put()), "Open offline SOFTWARE hive");
        if (!keyExists(software.get(), L"Microsoft\\Windows NT\\CurrentVersion") || !keyExists(software.get(), L"Classes\\CLSID"))
            throw std::runtime_error("The target does not have the expected Windows SOFTWARE structure");
        removed = removeRegistration(software.get());
        software.close();
    } catch (...) {
        const auto unloaded = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, mount.c_str());
        if (unloaded != ERROR_SUCCESS) std::cerr << "Offline hive remains mounted; unload failed with Windows error " << unloaded << '\n';
        throw;
    }
    require(RegUnLoadKeyW(HKEY_LOCAL_MACHINE, mount.c_str()), "Unload offline SOFTWARE hive");
    std::wcout << (removed ? L"Removed Sovereign filter registration.\n" : L"Sovereign filter registration was already absent.\n")
               << L"Offline Windows: " << root << L"\nProtected hive backup: " << backup
               << L"\nPIN enrollment, provider registration and encrypted profiles were preserved. Reboot to Windows.\n";
}
void createValue(HKEY parent, const wchar_t* path) {
    Key key;
    require(RegCreateKeyExW(parent, path, 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, key.put(), nullptr), "Create fixture key");
    constexpr DWORD marker = 0x534f5641;
    require(RegSetValueExW(key.get(), L"FixtureMarker", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&marker), sizeof(marker)), "Write fixture marker");
}
bool markerIntact(HKEY root, const wchar_t* path) {
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    return RegGetValueW(root, path, L"FixtureMarker", RRF_RT_REG_DWORD, nullptr, &value, &bytes) == ERROR_SUCCESS && value == 0x534f5641;
}
void selfTest(const wchar_t* directory) {
    const auto file = std::wstring(directory) + L"\\recovery-fixture-" + uniqueName() + L".hive";
    Key hive;
    require(RegLoadAppKeyW(file.c_str(), hive.put(), KEY_ALL_ACCESS, REG_PROCESS_APPKEY, 0), "Create private fixture hive");
    constexpr wchar_t sibling[] = L"Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\{00000001-0000-0000-0000-000000000000}\\Child";
    constexpr wchar_t pin[] = L"Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{D6886603-9D2F-4EB2-B667-1971041FA96B}";
    constexpr wchar_t provider[] = L"Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{8C19C6D8-49BE-4D76-9DA8-FC6A09229B74}";
    constexpr wchar_t com[] = L"Classes\\CLSID\\{51583B4D-1D80-4692-B4EF-1C385FBCF22D}\\InprocServer32";
    for (const auto path : {SovereignFilterRegistration, sibling, pin, provider, com}) createValue(hive.get(), path);
    check(removeRegistration(hive.get()), "removes the exact filter registration from a real private hive");
    check(!keyExists(hive.get(), SovereignFilterRegistration), "removed registration is absent");
    for (const auto path : {sibling, pin, provider, com}) check(markerIntact(hive.get(), path), "unrelated registration and marker are preserved");
    check(!removeRegistration(hive.get()), "repeated removal is idempotent");
    const auto unexpected = std::wstring(SovereignFilterRegistration) + L"\\UnexpectedChild";
    createValue(hive.get(), unexpected.c_str());
    bool rejected = false;
    try { (void)removeRegistration(hive.get()); } catch (const std::runtime_error&) { rejected = true; }
    check(rejected && markerIntact(hive.get(), unexpected.c_str()), "unexpected children stop non-recursive recovery");
    hive.close();
    require(RegLoadAppKeyW(file.c_str(), hive.put(), KEY_READ, REG_PROCESS_APPKEY, 0), "Reopen private fixture hive");
    check(markerIntact(hive.get(), sibling) && markerIntact(hive.get(), pin), "preserved data survives unloading and reopening the hive");
    hive.close();
    // Only this newly created fixture file is removed; no directory deletion.
    check(DeleteFileW(file.c_str()) != FALSE, "private fixture is removed after its handles close");
}
}
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 3 && std::wstring(argv[1]) == L"--self-test") selfTest(argv[2]);
        else if (argc == 3 && std::wstring(argv[1]) == L"--remove-filter") recover(argv[2]);
        else { std::cout << "Usage: swa_filter_recovery --remove-filter C:\\Windows (from WinRE/WinPE)\n"; return 2; }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
