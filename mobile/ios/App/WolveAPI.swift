import Foundation
import Security

/// Device token is kept in the Keychain (not in plain UserDefaults).
enum Keychain {
    private static let service = "ae.wolve.shield"
    static func save(_ value: String, for key: String) {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = Data(value.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }
    static func load(_ key: String) -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key,
                                kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    static func delete(_ key: String) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: key] as CFDictionary)
    }
}

struct APIError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct SmsCheck: Decodable {
    let action: String
    let risk_score: Int
    let classification: String
    let reasons: [String]
}

struct CallerCheck: Decodable {
    let number: String
    let registered_region: String?
    let warn: Bool
    let level: String
    let label: String
    let risk_score: Int
    let reasons: [String]
    let advice: String
    let note: String
}

private struct DirectoryResponse: Decodable { let entries: [DirectoryEntry] }
private struct RegisterResponse: Decodable { let device_id: String; let token: String }
private struct ErrorBody: Decodable { let detail: String }

/// Talks to the WOLVE server. Requests ask for Arabic (`X-WOLVE-Lang: ar`) so labels and reasons come back in Arabic.
final class WolveAPI {
    var baseURL: URL
    var token: String? { Keychain.load("deviceToken") }

    init(baseURL: URL) { self.baseURL = baseURL }

    private func request(_ path: String, method: String = "GET", body: Encodable? = nil, user: String? = nil) async throws -> Data {
        guard let url = URL(string: path, relativeTo: baseURL) else { throw APIError(message: "عنوان الخادم غير صحيح") }
        var req = URLRequest(url: url, timeoutInterval: 15)
        req.httpMethod = method
        req.setValue("ar", forHTTPHeaderField: "X-WOLVE-Lang")
        if let token { req.setValue(token, forHTTPHeaderField: "X-Device-Token") }
        if let user { req.setValue(user, forHTTPHeaderField: "X-WOLVE-User") }
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONEncoder().encode(body)
        }
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await URLSession.shared.data(for: req)
        } catch {
            throw APIError(message: "تعذّر الاتصال بخادم WOLVE. تأكد أن الجوال والكمبيوتر على نفس الشبكة.")
        }
        guard let http = response as? HTTPURLResponse else { throw APIError(message: "رد غير متوقع من الخادم") }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.detail
            throw APIError(message: detail ?? "خطأ من الخادم (\(http.statusCode))")
        }
        return data
    }

    func register(pairingCode: String, deviceName: String) async throws {
        struct Body: Encodable { let pairing_code: String; let device_name: String; let consent: Bool }
        let data = try await request("/api/mobile/register", method: "POST", body: Body(pairing_code: pairingCode, device_name: deviceName, consent: true))
        let r = try JSONDecoder().decode(RegisterResponse.self, from: data)
        Keychain.save(r.token, for: "deviceToken")
    }

    /// Unlink this phone and delete its data on the server (Apple requires in-app data deletion).
    func deleteDevice() async throws {
        _ = try await request("/api/mobile/device", method: "DELETE")
        Keychain.delete("deviceToken")
    }

    func syncProtection() async throws -> (rules: Int, numbers: Int) {
        let config = try JSONDecoder().decode(FilterConfig.self, from: try await request("/api/mobile/filter-config"))
        try SharedStore.saveConfig(config)
        let dir = try JSONDecoder().decode(DirectoryResponse.self, from: try await request("/api/mobile/call-directory"))
        try SharedStore.saveDirectory(dir.entries)
        return (config.blocked_domains.count + config.blocked_phones.count, dir.entries.count)
    }

    func checkMessage(sender: String, body: String) async throws -> SmsCheck {
        struct Body: Encodable { let sender: String; let body: String }
        return try JSONDecoder().decode(SmsCheck.self, from: try await request("/api/mobile/sms/classify", method: "POST", body: Body(sender: sender, body: body)))
    }

    func checkCaller(_ number: String) async throws -> CallerCheck {
        var comps = URLComponents()
        comps.path = "/api/mobile/caller-check"
        comps.queryItems = [URLQueryItem(name: "number", value: number)]
        let path = comps.string?.replacingOccurrences(of: "+", with: "%2B") ?? ""
        return try JSONDecoder().decode(CallerCheck.self, from: try await request(path))
    }
}
