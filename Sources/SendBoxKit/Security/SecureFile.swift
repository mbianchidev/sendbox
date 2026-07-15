import Foundation

#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

enum SecureFileError: Error, LocalizedError {
    case operationFailed(operation: String, path: String, code: Int32)

    var errorDescription: String? {
        switch self {
        case .operationFailed(let operation, let path, let code):
            return "\(operation) failed for \(path) (errno \(code): \(errorMessage(code)))"
        }
    }

    private func errorMessage(_ code: Int32) -> String {
        guard let message = strerror(code) else {
            return "unknown error"
        }
        return String(cString: message)
    }
}

enum SecureFile {
    static func create(
        at url: URL,
        data: Data,
        permissions: mode_t = 0o600
    ) throws {
        let descriptor = url.path.withCString {
            systemOpen($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, permissions)
        }
        guard descriptor >= 0 else {
            throw failure("open", url, errno)
        }

        do {
            guard systemFchmod(descriptor, permissions) == 0 else {
                throw failure("fchmod", url, errno)
            }
            try write(data, to: descriptor, path: url)
            guard systemFsync(descriptor) == 0 else {
                throw failure("fsync", url, errno)
            }
            guard systemClose(descriptor) == 0 else {
                throw failure("close", url, errno)
            }
        } catch {
            _ = systemClose(descriptor)
            try? FileManager.default.removeItem(at: url)
            throw error
        }
    }

    static func replaceAtomically(
        at url: URL,
        data: Data,
        permissions: mode_t = 0o600
    ) throws {
        let temporaryURL = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        try create(at: temporaryURL, data: data, permissions: permissions)

        let result = temporaryURL.path.withCString { source in
            url.path.withCString { destination in
                systemRename(source, destination)
            }
        }
        guard result == 0 else {
            let code = errno
            try? FileManager.default.removeItem(at: temporaryURL)
            throw failure("rename", url, code)
        }
    }

    static func ensureDirectory(
        at url: URL,
        permissions: mode_t = 0o700
    ) throws {
        let createResult = url.path.withCString {
            systemMkdir($0, permissions)
        }
        if createResult != 0 && errno != EEXIST {
            throw failure("mkdir", url, errno)
        }

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory),
            isDirectory.boolValue
        else {
            throw SecureFileError.operationFailed(
                operation: "validate directory",
                path: url.path,
                code: ENOTDIR
            )
        }

        let chmodResult = url.path.withCString {
            systemChmod($0, permissions)
        }
        guard chmodResult == 0 else {
            throw failure("chmod", url, errno)
        }
    }

    private static func write(
        _ data: Data,
        to descriptor: Int32,
        path: URL
    ) throws {
        try data.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else {
                return
            }

            var offset = 0
            while offset < bytes.count {
                let result = systemWrite(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    bytes.count - offset
                )
                if result < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw failure("write", path, errno)
                }
                offset += result
            }
        }
    }

    private static func failure(
        _ operation: String,
        _ url: URL,
        _ code: Int32
    ) -> SecureFileError {
        .operationFailed(operation: operation, path: url.path, code: code)
    }

    private static func systemOpen(
        _ path: UnsafePointer<CChar>,
        _ flags: Int32,
        _ mode: mode_t
    ) -> Int32 {
        #if canImport(Glibc)
        Glibc.open(path, flags, mode)
        #else
        Darwin.open(path, flags, mode)
        #endif
    }

    private static func systemWrite(
        _ descriptor: Int32,
        _ buffer: UnsafeRawPointer,
        _ count: Int
    ) -> Int {
        #if canImport(Glibc)
        Glibc.write(descriptor, buffer, count)
        #else
        Darwin.write(descriptor, buffer, count)
        #endif
    }

    private static func systemFchmod(_ descriptor: Int32, _ mode: mode_t) -> Int32 {
        #if canImport(Glibc)
        Glibc.fchmod(descriptor, mode)
        #else
        Darwin.fchmod(descriptor, mode)
        #endif
    }

    private static func systemFsync(_ descriptor: Int32) -> Int32 {
        #if canImport(Glibc)
        Glibc.fsync(descriptor)
        #else
        Darwin.fsync(descriptor)
        #endif
    }

    private static func systemClose(_ descriptor: Int32) -> Int32 {
        #if canImport(Glibc)
        Glibc.close(descriptor)
        #else
        Darwin.close(descriptor)
        #endif
    }

    private static func systemRename(
        _ source: UnsafePointer<CChar>,
        _ destination: UnsafePointer<CChar>
    ) -> Int32 {
        #if canImport(Glibc)
        Glibc.rename(source, destination)
        #else
        Darwin.rename(source, destination)
        #endif
    }

    private static func systemMkdir(
        _ path: UnsafePointer<CChar>,
        _ mode: mode_t
    ) -> Int32 {
        #if canImport(Glibc)
        Glibc.mkdir(path, mode)
        #else
        Darwin.mkdir(path, mode)
        #endif
    }

    private static func systemChmod(
        _ path: UnsafePointer<CChar>,
        _ mode: mode_t
    ) -> Int32 {
        #if canImport(Glibc)
        Glibc.chmod(path, mode)
        #else
        Darwin.chmod(path, mode)
        #endif
    }
}
