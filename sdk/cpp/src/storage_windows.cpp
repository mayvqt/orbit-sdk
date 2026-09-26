#include "storage_windows.hpp"

#include "storage_codec.hpp"
#include "installed_storage.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#include <aclapi.h>
#endif

namespace orbit::detail::storage_windows {
namespace {

[[noreturn]] void storage_failure() {
    throw Error(1, ErrorKind::storage, "storage", {});
}
#if defined(_WIN32)

#ifdef ORBIT_SDK_TESTING
std::atomic<InstalledWriteFault> installed_write_fault{InstalledWriteFault::none};
void inject_installed_write_fault(InstalledWriteFault stage) {
    if (installed_write_fault.load() == stage) storage_failure();
}
#endif

[[noreturn]] void installed_corrupt() {
    throw Error(1, ErrorKind::corrupt_state, "installation_state_corrupt", {});
}

constexpr wchar_t kLockName[] = L"orbit-storage.lock";
constexpr wchar_t kDataName[] = L"orbit-storage.bin";
constexpr std::size_t kMaximumCiphertext = 64 * 1024;
constexpr std::size_t kMaximumPlaintext = 32 * 1024;
constexpr DWORD kReparse = FILE_ATTRIBUTE_REPARSE_POINT;

class Handle {
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            reset();
            value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE);
        }
        return *this;
    }
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ != INVALID_HANDLE_VALUE && value_ != nullptr; }
    void reset() {
        if (*this) {
            CloseHandle(value_);
            value_ = INVALID_HANDLE_VALUE;
        }
    }

private:
    HANDLE value_ = INVALID_HANDLE_VALUE;
};

std::wstring utf8_to_wide(std::string_view input) {
    if (input.empty() || input.size() > static_cast<std::size_t>(INT_MAX) ||
        input.find('\0') != std::string_view::npos) {
        storage_failure();
    }
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                            input.data(), static_cast<int>(input.size()),
                                            nullptr, 0);
    if (needed <= 0) {
        storage_failure();
    }
    std::wstring output(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                            static_cast<int>(input.size()), output.data(), needed) != needed) {
        storage_failure();
    }
    return output;
}

bool local_drive(wchar_t letter) {
    if (!((letter >= L'a' && letter <= L'z') ||
          (letter >= L'A' && letter <= L'Z'))) {
        return false;
    }
    wchar_t root[] = {letter, L':', L'\\', L'\0'};
    const auto kind = GetDriveTypeW(root);
    return kind == DRIVE_FIXED || kind == DRIVE_RAMDISK || kind == DRIVE_REMOVABLE;
}

std::wstring normalize_directory(std::wstring path) {
    std::replace(path.begin(), path.end(), L'/', L'\\');
    if (path.size() < 4 || path[1] != L':' || path[2] != L'\\' ||
        path[0] == L'\\' || path[0] == L'.' || !local_drive(path[0]) ||
        path.rfind(L"\\\\", 0) == 0) {
        storage_failure();
    }
    if (path.size() > 3 && path.back() == L'\\') {
        path.pop_back();
    }
    if (path.size() <= 3) {
        storage_failure();
    }
    std::size_t part_begin = 3;
    while (part_begin < path.size()) {
        const auto separator = path.find(L'\\', part_begin);
        const auto part_end = separator == std::wstring::npos ? path.size() : separator;
        const auto length = part_end - part_begin;
        if (length == 0 || (length == 1 && path[part_begin] == L'.') ||
            (length == 2 && path[part_begin] == L'.' && path[part_begin + 1] == L'.') ||
            path[part_end - 1] == L'.' || path[part_end - 1] == L' ' ||
            std::find(path.begin() + static_cast<std::ptrdiff_t>(part_begin),
                      path.begin() + static_cast<std::ptrdiff_t>(part_end), L':') !=
                path.begin() + static_cast<std::ptrdiff_t>(part_end)) {
            storage_failure();
        }
        if (separator == std::wstring::npos) {
            break;
        }
        part_begin = separator + 1;
    }
    return path;
}

std::vector<std::wstring> directory_paths(const std::wstring& directory) {
    std::vector<std::wstring> paths;
    paths.emplace_back(directory.substr(0, 3));
    std::size_t cursor = 3;
    while (cursor < directory.size()) {
        const auto separator = directory.find(L'\\', cursor);
        const auto end = separator == std::wstring::npos ? directory.size() : separator;
        paths.emplace_back(directory.substr(0, end));
        if (separator == std::wstring::npos) {
            break;
        }
        cursor = separator + 1;
    }
    return paths;
}

Handle open_handle(const std::wstring& path, DWORD access, DWORD sharing,
                   DWORD disposition, DWORD flags = 0, SECURITY_ATTRIBUTES* security = nullptr) {
    if (path.size() >= 32767) {
        storage_failure();
    }
    std::wstring long_path;
    const std::wstring* native_path = &path;
    if (path.size() >= 248 && path.rfind(L"\\\\?\\", 0) != 0) {
        long_path = L"\\\\?\\" + path;
        native_path = &long_path;
    }
    return Handle(CreateFileW(native_path->c_str(), access, sharing, security, disposition,
                              flags | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
}

BY_HANDLE_FILE_INFORMATION file_info(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileType(handle) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(handle, &info)) {
        storage_failure();
    }
    return info;
}


void check_directory(HANDLE handle) {
    const auto info = file_info(handle);
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (info.dwFileAttributes & kReparse) != 0) {
        storage_failure();
    }
}

void check_regular(HANDLE handle) {
    const auto info = file_info(handle);
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | kReparse)) != 0 ||
        info.nNumberOfLinks != 1) {
        storage_failure();
    }
}

struct WindowsIdentity {
    std::vector<unsigned char> user_buffer;
    std::array<unsigned char, SECURITY_MAX_SID_SIZE> system_buffer{};
    std::array<unsigned char, SECURITY_MAX_SID_SIZE> administrators_buffer{};
    PSID user = nullptr;
    PSID system = nullptr;
    PSID administrators = nullptr;

    WindowsIdentity() {
        HANDLE thread_token = nullptr;
        if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &thread_token)) {
            CloseHandle(thread_token);
            storage_failure();
        }
        if (GetLastError() != ERROR_NO_TOKEN) storage_failure();
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) storage_failure();
        Handle token_handle(token);
        DWORD bytes = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
        if (bytes == 0 || bytes > 65536) storage_failure();
        user_buffer.resize(bytes);
        if (!GetTokenInformation(token, TokenUser, user_buffer.data(), bytes, &bytes)) storage_failure();
        user = reinterpret_cast<TOKEN_USER*>(user_buffer.data())->User.Sid;
        DWORD system_size = static_cast<DWORD>(system_buffer.size());
        DWORD admin_size = static_cast<DWORD>(administrators_buffer.size());
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_buffer.data(), &system_size) ||
            !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
                                administrators_buffer.data(), &admin_size)) storage_failure();
        system = system_buffer.data();
        administrators = administrators_buffer.data();
    }
};

bool private_acl(HANDLE handle, bool require_protected) {
    WindowsIdentity identity;
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto status = GetSecurityInfo(handle, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor);
    if (status != ERROR_SUCCESS || descriptor == nullptr) {
        if (descriptor) LocalFree(descriptor);
        return false;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    bool valid = owner != nullptr && EqualSid(owner, identity.user) &&
        GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) &&
        present && dacl != nullptr && IsValidAcl(dacl) &&
        GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        (!require_protected || (control & SE_DACL_PROTECTED) != 0);
    bool user_allowed = false;
    if (valid) {
        for (DWORD index = 0; index < dacl->AceCount; ++index) {
            void* raw = nullptr;
            if (!GetAce(dacl, index, &raw)) { valid = false; break; }
            const auto* header = static_cast<ACE_HEADER*>(raw);
            if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
                PSID sid = const_cast<DWORD*>(&ace->SidStart);
                if (!IsValidSid(sid) || (!EqualSid(sid, identity.user) && !EqualSid(sid, identity.system) &&
                    !EqualSid(sid, identity.administrators))) { valid = false; break; }
                if (EqualSid(sid, identity.user) && !(header->AceFlags & INHERIT_ONLY_ACE)) user_allowed = true;
            } else if (header->AceType != ACCESS_DENIED_ACE_TYPE) {
                valid = false;
                break;
            }
        }
    }
    LocalFree(descriptor);
    return valid && user_allowed;
}

class PrivateSecurity {
public:
    PrivateSecurity() {
        EXPLICIT_ACCESSW entries[3]{};
        const PSID sids[3] = {identity_.user, identity_.system, identity_.administrators};
        for (int i = 0; i < 3; ++i) {
            entries[i].grfAccessPermissions = FILE_ALL_ACCESS;
            entries[i].grfAccessMode = SET_ACCESS;
            entries[i].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            entries[i].Trustee.TrusteeType = i == 2 ? TRUSTEE_IS_GROUP : TRUSTEE_IS_USER;
            entries[i].Trustee.ptstrName = static_cast<LPWSTR>(sids[i]);
        }
        PACL dacl = nullptr;
        if (SetEntriesInAclW(3, entries, nullptr, &dacl) != ERROR_SUCCESS) storage_failure();
        acl_.reset(dacl);
        if (!InitializeSecurityDescriptor(&descriptor_, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorOwner(&descriptor_, identity_.user, FALSE) ||
            !SetSecurityDescriptorDacl(&descriptor_, TRUE, dacl, FALSE) ||
            !SetSecurityDescriptorControl(&descriptor_, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
            storage_failure();
        }
        attributes_ = {sizeof(SECURITY_ATTRIBUTES), &descriptor_, FALSE};
    }
    SECURITY_ATTRIBUTES* attributes() noexcept { return &attributes_; }
private:
    WindowsIdentity identity_;
    std::unique_ptr<void, decltype(&LocalFree)> acl_{nullptr, &LocalFree};
    SECURITY_DESCRIPTOR descriptor_{};
    SECURITY_ATTRIBUTES attributes_{};
};

std::pair<std::wstring, std::vector<Handle>> create_or_pin_private_directory(const std::wstring& directory) {
    const auto normalized = normalize_directory(directory);
    const auto paths = directory_paths(normalized);
    if (paths.empty()) storage_failure();
    std::vector<Handle> pinned;
    PrivateSecurity security;
    for (std::size_t index = 0; index < paths.size(); ++index) {
        auto handle = open_handle(paths[index], READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS);
        if (!handle && GetLastError() == ERROR_FILE_NOT_FOUND) {
            if (!CreateDirectoryW(paths[index].c_str(), security.attributes()) &&
                GetLastError() != ERROR_ALREADY_EXISTS) storage_failure();
            handle = open_handle(paths[index], READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS);
        }
        if (!handle) storage_failure();
        check_directory(handle.get());
        if (index + 1 == paths.size() && !private_acl(handle.get(), true)) storage_failure();
        pinned.push_back(std::move(handle));
    }
    return {normalized, std::move(pinned)};
}

void check_private_file(HANDLE handle) {
    check_regular(handle);
    if (!private_acl(handle, false)) storage_failure();
}

std::vector<Handle> pin_directories(const std::wstring& directory) {
    std::vector<Handle> handles;
    for (const auto& path : directory_paths(directory)) {
        auto handle = open_handle(path, FILE_READ_ATTRIBUTES | READ_CONTROL,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS);
        if (!handle) {
            storage_failure();
        }
        check_directory(handle.get());
        handles.push_back(std::move(handle));
    }
    return handles;
}

struct DpapiBlob {
    DATA_BLOB value{};
    ~DpapiBlob() {
        if (value.pbData != nullptr) {
            SecureZeroMemory(value.pbData, value.cbData);
            LocalFree(value.pbData);
        }
    }
};

class PlaintextWiper {
public:
    explicit PlaintextWiper(std::string& value) : value_(value) {}
    ~PlaintextWiper() {
        if (!value_.empty()) {
            SecureZeroMemory(value_.data(), value_.size());
        }
    }
    PlaintextWiper(const PlaintextWiper&) = delete;
    PlaintextWiper& operator=(const PlaintextWiper&) = delete;

private:
    std::string& value_;
};

DATA_BLOB borrowed_blob(std::string_view bytes) {
    if (bytes.size() > MAXDWORD) {
        storage_failure();
    }
    return DATA_BLOB{static_cast<DWORD>(bytes.size()),
                     reinterpret_cast<BYTE*>(const_cast<char*>(bytes.data()))};
}

std::string protect(std::string_view plaintext, const std::array<unsigned char, 32>& entropy) {
    if (plaintext.size() > kMaximumPlaintext) {
        storage_failure();
    }
    auto input = borrowed_blob(plaintext);
    auto optional_entropy = DATA_BLOB{static_cast<DWORD>(entropy.size()),
                                      const_cast<BYTE*>(entropy.data())};
    DpapiBlob output;
    if (!CryptProtectData(&input, nullptr, &optional_entropy, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &output.value) ||
        output.value.cbData == 0 || output.value.cbData > kMaximumCiphertext ||
        output.value.pbData == nullptr) {
        storage_failure();
    }
    return std::string(reinterpret_cast<const char*>(output.value.pbData),
                        output.value.cbData);
}

std::string protect_installed(std::string_view plaintext,
                              const std::array<unsigned char, 32>& entropy) {
    constexpr std::size_t maximum_ciphertext = 128 * 1024;
    if (plaintext.empty() || plaintext.size() > 64 * 1024) storage_failure();
    auto input = borrowed_blob(plaintext);
    auto optional_entropy = DATA_BLOB{static_cast<DWORD>(entropy.size()),
                                      const_cast<BYTE*>(entropy.data())};
    DpapiBlob output;
    if (!CryptProtectData(&input, nullptr, &optional_entropy, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &output.value) ||
        output.value.cbData == 0 || output.value.cbData > maximum_ciphertext ||
        output.value.pbData == nullptr) storage_failure();
    return std::string(reinterpret_cast<const char*>(output.value.pbData),
                        output.value.cbData);
}

std::string unprotect_installed(std::string_view ciphertext,
                                const std::array<unsigned char, 32>& entropy) {
    constexpr std::size_t maximum_ciphertext = 128 * 1024;
    if (ciphertext.empty() || ciphertext.size() > maximum_ciphertext) storage_failure();
    auto input = borrowed_blob(ciphertext);
    auto optional_entropy = DATA_BLOB{static_cast<DWORD>(entropy.size()),
                                      const_cast<BYTE*>(entropy.data())};
    DpapiBlob output;
    if (!CryptUnprotectData(&input, nullptr, &optional_entropy, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &output.value) ||
        output.value.cbData == 0 || output.value.cbData > 64 * 1024 ||
        output.value.pbData == nullptr) storage_failure();
    return std::string(reinterpret_cast<const char*>(output.value.pbData),
                        output.value.cbData);
}

std::string unprotect(std::string_view ciphertext,
                      const std::array<unsigned char, 32>& entropy) {
    if (ciphertext.empty() || ciphertext.size() > kMaximumCiphertext) {
        storage_failure();
    }
    auto input = borrowed_blob(ciphertext);
    auto optional_entropy = DATA_BLOB{static_cast<DWORD>(entropy.size()),
                                      const_cast<BYTE*>(entropy.data())};
    DpapiBlob output;
    if (!CryptUnprotectData(&input, nullptr, &optional_entropy, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &output.value) ||
        output.value.cbData > kMaximumPlaintext ||
        (output.value.cbData != 0 && output.value.pbData == nullptr)) {
        storage_failure();
    }
    return std::string(reinterpret_cast<const char*>(output.value.pbData),
                        output.value.cbData);
}

std::string read_file(HANDLE handle, std::size_t maximum = kMaximumCiphertext) {
    check_regular(handle);
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle, &size) || size.QuadPart <= 0 ||
        static_cast<unsigned long long>(size.QuadPart) > maximum) {
        storage_failure();
    }
    std::string output(static_cast<std::size_t>(size.QuadPart), '\0');
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(
            output.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD read = 0;
        if (!ReadFile(handle, output.data() + offset, chunk, &read, nullptr) || read == 0) {
            storage_failure();
        }
        offset += read;
    }
    char extra = 0;
    DWORD read = 0;
    if (!ReadFile(handle, &extra, 1, &read, nullptr) || read != 0) {
        storage_failure();
    }
    return output;
}

std::string hex_lower(const unsigned char* bytes, std::size_t length) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        output.push_back(digits[bytes[i] >> 4]);
        output.push_back(digits[bytes[i] & 15]);
    }
    return output;
}

class TemporaryFile {
public:
    TemporaryFile(std::wstring path, Handle file)
        : path_(std::move(path)), file_(std::move(file)) {}
    ~TemporaryFile() {
        if (!installed_ && file_) {
            FILE_DISPOSITION_INFO disposition{TRUE};
            SetFileInformationByHandle(file_.get(), FileDispositionInfo,
                                       &disposition, sizeof(disposition));
        }
    }
    HANDLE get() const { return file_.get(); }
    void installed() { installed_ = true; }

private:
    std::wstring path_;
    Handle file_;
    bool installed_ = false;
};

void atomic_replace(HANDLE directory, const std::wstring& directory_path,
                    std::string_view bytes, bool allow_missing,
                    const std::wstring& destination_name = kDataName,
                    bool require_private_acl = false) {
    check_directory(directory);
    if (require_private_acl && !private_acl(directory, true)) storage_failure();
    const auto destination = directory_path + L"\\" + destination_name;
    auto existing = open_handle(destination, FILE_READ_ATTRIBUTES | READ_CONTROL, 0, OPEN_EXISTING);
    if (existing) {
        if (require_private_acl) check_private_file(existing.get());
        else check_regular(existing.get());
        existing.reset();
    } else if (GetLastError() != ERROR_FILE_NOT_FOUND || !allow_missing) {
        storage_failure();
    }

    std::array<unsigned char, 16> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
        storage_failure();
    }
    const auto suffix = hex_lower(random.data(), random.size());
    const auto temporary_path = directory_path + L"\\orbit-storage-" +
        std::wstring(suffix.begin(), suffix.end()) + L".tmp";
    std::unique_ptr<PrivateSecurity> security;
    if (require_private_acl) security = std::make_unique<PrivateSecurity>();
    auto file = open_handle(temporary_path, GENERIC_WRITE | DELETE | READ_CONTROL, 0,
                            CREATE_NEW, FILE_FLAG_WRITE_THROUGH,
                            security ? security->attributes() : nullptr);
    if (!file) {
        storage_failure();
    }
    if (require_private_acl) check_private_file(file.get());
    else check_regular(file.get());
    TemporaryFile temporary(temporary_path, std::move(file));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(
            bytes.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(temporary.get(), bytes.data() + offset, chunk, &written, nullptr) ||
            written == 0) {
            storage_failure();
        }
        offset += written;
    }
    if (!FlushFileBuffers(temporary.get())) {
        storage_failure();
    }

#ifdef ORBIT_SDK_TESTING
    if (require_private_acl) inject_installed_write_fault(InstalledWriteFault::temporary_written);
#endif
    DWORD path_length = GetFinalPathNameByHandleW(directory, nullptr, 0, 0);
    if (path_length == 0 || path_length > 32768) {
        storage_failure();
    }
    std::wstring pinned(path_length, L'\0');
    const DWORD actual = GetFinalPathNameByHandleW(directory, pinned.data(), path_length, 0);
    if (actual == 0 || actual >= path_length) {
        storage_failure();
    }
    pinned.resize(actual);
    if (!pinned.empty() && pinned.back() != L'\\') {
        pinned.push_back(L'\\');
    }
    pinned.append(destination_name);
    const auto name_bytes = pinned.size() * sizeof(wchar_t);
    const auto file_name_offset = offsetof(FILE_RENAME_INFO, FileName);
    const auto max_dword = static_cast<std::size_t>(MAXDWORD);
    const auto max_size = std::numeric_limits<std::size_t>::max();
    if (name_bytes > max_dword - sizeof(wchar_t) ||
        name_bytes > max_size - sizeof(wchar_t)) {
        storage_failure();
    }
    const auto tail_bytes = name_bytes + sizeof(wchar_t);
    if (tail_bytes > max_dword - file_name_offset ||
        tail_bytes > max_size - file_name_offset) {
        storage_failure();
    }
    const auto total = file_name_offset + tail_bytes;
    std::vector<std::max_align_t> buffer(
        (total + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    info->ReplaceIfExists = TRUE;
    info->RootDirectory = nullptr;
    info->FileNameLength = static_cast<DWORD>(name_bytes);
    std::memcpy(info->FileName, pinned.data(), name_bytes);
    info->FileName[pinned.size()] = L'\0';
    if (!SetFileInformationByHandle(temporary.get(), FileRenameInfo, info,
                                    static_cast<DWORD>(total))) {
        storage_failure();
    }
    temporary.installed();
    if (!FlushFileBuffers(temporary.get())) {
        storage_failure();
    }
    if (require_private_acl) {
        auto installed = open_handle(destination, FILE_READ_ATTRIBUTES | READ_CONTROL, 0, OPEN_EXISTING);
        if (!installed) storage_failure();
        check_private_file(installed.get());
    }
}

class WindowsStorage final : public CredentialStorage {
public:
    static std::shared_ptr<CredentialStorage> open(const Config& config) {
        const auto directory_path = normalize_directory(utf8_to_wide(config.storage.path));
        (void)storage_codec::encode(config, 0, std::nullopt);
        auto directories = pin_directories(directory_path);
        if (directories.empty()) {
            storage_failure();
        }
        const auto lock_path = directory_path + L"\\" + kLockName;
        auto lease = open_handle(lock_path, GENERIC_READ | GENERIC_WRITE, 0,
                                 CREATE_NEW);
        bool new_lease = static_cast<bool>(lease);
        if (!lease && (GetLastError() == ERROR_FILE_EXISTS ||
                       GetLastError() == ERROR_ALREADY_EXISTS)) {
            lease = open_handle(lock_path, GENERIC_READ | GENERIC_WRITE, 0,
                                OPEN_EXISTING);
        }
        if (!lease) {
            storage_failure();
        }
        check_regular(lease.get());
        LARGE_INTEGER lease_size{};
        if (!GetFileSizeEx(lease.get(), &lease_size) || lease_size.QuadPart != 0) {
            storage_failure();
        }
        if (new_lease && !FlushFileBuffers(lease.get())) {
            storage_failure();
        }
        auto result = std::shared_ptr<WindowsStorage>(new WindowsStorage(
            config, directory_path, storage_codec::entropy(config),
            std::move(directories), std::move(lease), new_lease));
        result->check();
        auto existing = result->read_ciphertext();
        if (existing) {
            auto plaintext = unprotect(*existing, result->entropy_);
            PlaintextWiper wipe(plaintext);
            const auto decoded = storage_codec::decode(config, plaintext);
            result->generation_ = decoded.first;
            result->credential_ = decoded.second;
        } else if (new_lease) {
            result->commit(0, std::nullopt);
        } else {
            storage_failure();
        }
        result->allow_missing_ = false;
        return result;
    }

    std::uint64_t version() override {
        std::lock_guard<std::mutex> lock(mutex_);
        check();
        return generation_;
    }

    std::pair<std::uint64_t, std::optional<Json::Value>> load() override {
        std::lock_guard<std::mutex> lock(mutex_);
        check();
        return {generation_, credential_};
    }

    void save(std::uint64_t expected_version,
              const Json::Value& credential) override {
        std::lock_guard<std::mutex> lock(mutex_);
        check();
        if (expected_version != generation_) {
            throw Error(1, ErrorKind::stale_response, "stale_response", {});
        }
        commit(generation_, credential);
    }

    std::uint64_t invalidate() override {
        std::lock_guard<std::mutex> lock(mutex_);
        check();
        if (generation_ == storage_codec::max_generation) {
            poison();
            storage_failure();
        }
        const auto next = generation_ + 1;
        commit(next, std::nullopt);
        return next;
    }

private:
    WindowsStorage(const Config& config, std::wstring directory_path,
                   std::array<unsigned char, 32> entropy,
                   std::vector<Handle> directories, Handle lease,
                   bool allow_missing)
        : config_(config), directory_path_(std::move(directory_path)),
          entropy_(entropy), directories_(std::move(directories)),
          lease_(std::move(lease)), allow_missing_(allow_missing) {}

    void check() {
        if (poisoned_ || directories_.empty() || !lease_) {
            storage_failure();
        }
        for (const auto& directory : directories_) {
            check_directory(directory.get());
        }
        check_regular(lease_.get());
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(lease_.get(), &size) || size.QuadPart != 0) {
            poison();
            storage_failure();
        }
    }

    void poison() {
        poisoned_ = true;
        credential_.reset();
    }

    std::optional<std::string> read_ciphertext() {
        check();
        auto file = open_handle(directory_path_ + L"\\" + kDataName,
                                GENERIC_READ, 0, OPEN_EXISTING);
        if (!file && GetLastError() == ERROR_FILE_NOT_FOUND) {
            return std::nullopt;
        }
        if (!file) {
            storage_failure();
        }
        return read_file(file.get());
    }

    void commit(std::uint64_t generation,
                const std::optional<Json::Value>& credential) {
        try {
            check();
            auto plaintext = storage_codec::encode(config_, generation, credential);
            PlaintextWiper wipe(plaintext);
            const auto ciphertext = protect(plaintext, entropy_);
            check();
            atomic_replace(directories_.back().get(), directory_path_, ciphertext,
                           allow_missing_);
            allow_missing_ = false;
            generation_ = generation;
            credential_ = credential;
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::stale_response) {
                throw;
            }
            poison();
            storage_failure();
        } catch (...) {
            poison();
            storage_failure();
        }
    }

    Config config_;
    std::wstring directory_path_;
    std::array<unsigned char, 32> entropy_{};
    std::vector<Handle> directories_;
    Handle lease_;
    std::mutex mutex_;
    std::uint64_t generation_ = 0;
    std::optional<Json::Value> credential_;
    bool allow_missing_ = false;
    bool poisoned_ = false;
};


class WindowsInstalledStorage final : public InstalledStorage {
public:
    static std::shared_ptr<InstalledStorage> open(std::string directory, const Config& config) {
        try {
            auto [normalized, directories] = create_or_pin_private_directory(utf8_to_wide(directory));
            if (directories.empty() || !private_acl(directories.back().get(), true)) storage_failure();
            const auto lock_path = normalized + L"\\" + kLockName;
            PrivateSecurity security;
            auto lease = open_handle(lock_path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                                     0, CREATE_NEW, FILE_FLAG_WRITE_THROUGH, security.attributes());
            const bool created = static_cast<bool>(lease);
            if (!lease && (GetLastError() == ERROR_FILE_EXISTS ||
                           GetLastError() == ERROR_ALREADY_EXISTS)) {
                lease = open_handle(lock_path,
                    GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, OPEN_EXISTING);
            }
            if (!lease) {
                if (GetLastError() == ERROR_SHARING_VIOLATION ||
                    GetLastError() == ERROR_LOCK_VIOLATION) {
                    throw Error(1, ErrorKind::installation_in_use,
                                "installation_in_use", {});
                }
                storage_failure();
            }
            check_private_file(lease.get());
            LARGE_INTEGER lease_size{};
            if (!GetFileSizeEx(lease.get(), &lease_size) || lease_size.QuadPart != 0) storage_failure();
            if (created && !FlushFileBuffers(lease.get())) storage_failure();
            auto result = std::shared_ptr<WindowsInstalledStorage>(
                new WindowsInstalledStorage(normalized, std::move(directories),
                                            std::move(lease), installed_entropy(config)));
            result->initialize_ = created;
            std::optional<std::string> bytes;
            try { bytes = result->read_record(); }
            catch (...) { installed_corrupt(); }
            if (created) {
                if (bytes) installed_corrupt();
            } else if (!bytes) {
                installed_corrupt();
            }
            return result;
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::installation_in_use ||
                error.kind() == ErrorKind::corrupt_state) throw;
            throw Error(1, ErrorKind::storage,
                        "installation_storage_unavailable", {});
        } catch (...) {
            throw Error(1, ErrorKind::storage,
                        "installation_storage_unavailable", {});
        }
    }

    bool initialization_needed() const noexcept override { return initialize_; }

    std::optional<std::string> load() override {
        try {
            const auto bytes = read_record();
            if (!bytes && !initialize_) installed_corrupt();
            if (!bytes) return std::nullopt;
            auto plaintext = unprotect_installed(*bytes, entropy_);
            PlaintextWiper wipe(plaintext);
            return std::string(plaintext);
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::corrupt_state) throw;
            throw Error(1, ErrorKind::corrupt_state,
                        "installation_state_corrupt", {});
        } catch (...) {
            throw Error(1, ErrorKind::corrupt_state,
                        "installation_state_corrupt", {});
        }
    }

    void initialize(std::string_view bytes) override {
        if (!initialize_) installed_corrupt();
        commit(bytes, true);
        initialize_ = false;
    }

    void save(std::string_view bytes) override {
        if (initialize_) installed_corrupt();
        commit(bytes, false);
    }

    std::string_view provider() const noexcept override { return "windows_dpapi"; }

private:
    WindowsInstalledStorage(std::wstring directory,
                            std::vector<Handle> directories, Handle lease,
                            std::array<unsigned char, 32> entropy)
        : directory_(std::move(directory)), directories_(std::move(directories)),
          lease_(std::move(lease)), entropy_(entropy) {}

    static std::array<unsigned char, 32> installed_entropy(const Config& config) {
        const auto hash = ::orbit::detail::installed_scope_hash(config);
        std::array<unsigned char, 32> output{};
        const auto nibble = [](char value) -> unsigned char {
            return static_cast<unsigned char>(value <= '9' ? value - '0' : value - 'a' + 10);
        };
        if (hash.size() != 64) storage_failure();
        for (std::size_t i = 0; i < output.size(); ++i) {
            output[i] = static_cast<unsigned char>((nibble(hash[2 * i]) << 4) |
                                                    nibble(hash[2 * i + 1]));
        }
        return output;
    }

    void check() {
        if (directories_.empty() || !lease_ ||
            !private_acl(directories_.back().get(), true)) storage_failure();
        for (const auto& directory : directories_) check_directory(directory.get());
        check_private_file(lease_.get());
        // The non-sharing lease and pinned non-delete-sharing ancestors
        // already prevent replacement. Reopening this lease would fail against
        // our own handle with ERROR_SHARING_VIOLATION.
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(lease_.get(), &size) || size.QuadPart != 0) storage_failure();
    }

    std::optional<std::string> read_record() {
        check();
        const auto path = directory_ + L"\\orbit-installed.state";
        auto file = open_handle(path, GENERIC_READ | READ_CONTROL, 0, OPEN_EXISTING);
        if (!file && GetLastError() == ERROR_FILE_NOT_FOUND) return std::nullopt;
        if (!file) storage_failure();
        check_private_file(file.get());
        return read_file(file.get(), 128 * 1024);
    }

    void write_marker(bool pending) {
        LARGE_INTEGER offset{};
        if (!SetFilePointerEx(lease_.get(), offset, nullptr, FILE_BEGIN)) storage_failure();
        if (pending) {
            const unsigned char marker = 1;
            DWORD written = 0;
            if (!WriteFile(lease_.get(), &marker, 1, &written, nullptr) || written != 1) storage_failure();
        } else if (!SetEndOfFile(lease_.get())) {
            storage_failure();
        }
        if (!FlushFileBuffers(lease_.get())) storage_failure();
    }

    void commit(std::string_view plaintext, bool allow_missing) {
        try {
            if (plaintext.empty() || plaintext.size() > 64 * 1024) storage_failure();
            check();
            const auto existing = read_record();
            if (!existing && !allow_missing) installed_corrupt();
            if (existing && allow_missing) installed_corrupt();
            write_marker(true);
#ifdef ORBIT_SDK_TESTING
            inject_installed_write_fault(InstalledWriteFault::fenced);
#endif
            const auto ciphertext = protect_installed(plaintext, entropy_);
            atomic_replace(directories_.back().get(), directory_, ciphertext,
                           allow_missing, L"orbit-installed.state", true);
#ifdef ORBIT_SDK_TESTING
            inject_installed_write_fault(InstalledWriteFault::replaced);
#endif
            write_marker(false);
            check();
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::corrupt_state) throw;
            throw Error(1, ErrorKind::storage,
                        "installation_state_write_failed", {});
        } catch (...) {
            throw Error(1, ErrorKind::storage,
                        "installation_state_write_failed", {});
        }
    }

    std::wstring directory_;
    std::vector<Handle> directories_;
    Handle lease_;
    std::array<unsigned char, 32> entropy_{};
    bool initialize_ = false;
};


#endif // _WIN32

} // namespace

#if defined(ORBIT_SDK_TESTING) && defined(_WIN32)
void set_installed_write_fault(InstalledWriteFault fault) {
    installed_write_fault.store(fault);
}
#endif

std::shared_ptr<InstalledStorage> open_installed(std::string directory,
                                                  const Config& config) {
#if defined(_WIN32)
    return WindowsInstalledStorage::open(std::move(directory), config);
#else
    (void)directory;
    (void)config;
    storage_failure();
#endif
}

std::shared_ptr<CredentialStorage> open(const Config& config) {
#if defined(_WIN32)
    return WindowsStorage::open(config);
#else
    (void)config;
    storage_failure();
#endif
}

} // namespace orbit::detail::storage_windows
