import IdentityLookup

/// SMS/MMS filter. iOS calls this ONLY for messages from senders that are not in your contacts,
/// and only after the user picks 3B in Settings → Apps → Messages → Unknown & Spam → SMS Filtering.
/// Scoring runs entirely on the phone with rules synced by the 3B app; the message is not uploaded.
final class MessageFilterExtension: ILMessageFilterExtension {}

extension MessageFilterExtension: ILMessageFilterQueryHandling {
    func handle(_ queryRequest: ILMessageFilterQueryRequest,
                context: ILMessageFilterExtensionContext,
                completion: @escaping (ILMessageFilterQueryResponse) -> Void) {
        let response = ILMessageFilterQueryResponse()
        let body = queryRequest.messageBody ?? ""
        if body.isEmpty {
            response.action = .none
        } else {
            let verdict = ScamRules.evaluate(sender: queryRequest.sender, body: body, config: SharedStore.loadConfig())
            if verdict.isJunk {
                response.action = .junk
                SharedStore.recordJunk()
            } else {
                response.action = .none  // let iOS decide (inbox / its own filters)
            }
        }
        completion(response)
    }
}
