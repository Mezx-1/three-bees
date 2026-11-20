import CallKit
import Foundation

/// Call Directory extension: before you answer, iOS shows the 3B label under the caller's number
/// (e.g. "⚠️ 3B: احتيال محتمل") or blocks numbers reported as scams.
/// Enable it in Settings → Apps → Phone → Call Blocking & Identification → 3B.
/// The list comes from the 3B app (synced from the server); iOS only supports exact numbers, not prefixes.
final class CallDirectoryHandler: CXCallDirectoryProvider {
    override func beginRequest(with context: CXCallDirectoryExtensionContext) {
        context.delegate = self
        if context.isIncremental {
            // Always do a full reload: simple and correct for lists of this size.
            context.removeAllBlockingEntries()
            context.removeAllIdentificationEntries()
        }
        let entries = SharedStore.loadDirectory()
        var blocked = Set<CXCallDirectoryPhoneNumber>()
        var labels: [CXCallDirectoryPhoneNumber: String] = [:]
        for e in entries {
            // CallKit wants the full international number as digits only, e.g. 971501234567.
            guard let n = CXCallDirectoryPhoneNumber(e.number.filter(\.isNumber)), n > 0 else { continue }
            if e.block { blocked.insert(n) } else { labels[n] = e.label }
        }
        // CallKit requires entries in strictly ascending numeric order.
        for n in blocked.sorted() {
            context.addBlockingEntry(withNextSequentialPhoneNumber: n)
        }
        for n in labels.keys.sorted() where !blocked.contains(n) {
            context.addIdentificationEntry(withNextSequentialPhoneNumber: n, label: labels[n] ?? "3B")
        }
        context.completeRequest()
    }
}

extension CallDirectoryHandler: CXCallDirectoryExtensionContextDelegate {
    func requestFailed(for extensionContext: CXCallDirectoryExtensionContext, withError error: Error) {
        // Nothing to clean up; the app shows the reload error to the user.
    }
}
