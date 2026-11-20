import Foundation

/// Data shared between the app and its extensions through the App Group container.
/// The app downloads rules from the 3B server; the extensions only read local files (they have no network access).
struct DirectoryEntry: Codable, Hashable {
    let number: String
    let label: String
    let block: Bool
}

enum SharedStore {
    static let appGroup = "group.ae.threebees.app"
    static let callDirectoryExtensionID = "ae.threebees.app.CallDirectory"

    private static var container: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }

    private static func read<T: Decodable>(_ name: String, as type: T.Type) -> T? {
        guard let url = container?.appendingPathComponent(name), let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    private static func write<T: Encodable>(_ value: T, to name: String) throws {
        guard let url = container?.appendingPathComponent(name) else { throw CocoaError(.fileNoSuchFile) }
        try JSONEncoder().encode(value).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }

    static func loadConfig() -> FilterConfig { read("filter-config.json", as: FilterConfig.self) ?? .builtIn }
    static func saveConfig(_ config: FilterConfig) throws { try write(config, to: "filter-config.json") }

    static func loadDirectory() -> [DirectoryEntry] { read("call-directory.json", as: [DirectoryEntry].self) ?? [] }
    static func saveDirectory(_ entries: [DirectoryEntry]) throws { try write(entries, to: "call-directory.json") }

    /// Counts how many messages the filter sent to Junk (no message content is stored).
    static func recordJunk() {
        let d = UserDefaults(suiteName: appGroup)
        d?.set((d?.integer(forKey: "junkCount") ?? 0) + 1, forKey: "junkCount")
    }
    static var junkCount: Int { UserDefaults(suiteName: appGroup)?.integer(forKey: "junkCount") ?? 0 }
}
