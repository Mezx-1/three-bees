import CallKit
import SwiftUI
import UIKit

struct ContentView: View {
    var body: some View {
        TabView {
            ProtectionView().tabItem { Label("الحماية", systemImage: "shield.lefthalf.filled") }
            CheckView().tabItem { Label("افحص", systemImage: "magnifyingglass") }
            SettingsView().tabItem { Label("الإعدادات", systemImage: "gearshape") }
        }
        .tint(Color(red: 0.11, green: 0.31, blue: 0.85))
    }
}

// MARK: - Protection status & setup

struct ProtectionView: View {
    @AppStorage("serverURL") private var serverURL = AppConfig.defaultServer
    @State private var callStatus = "…"
    @State private var syncing = false
    @State private var message: String?
    @State private var lastSync = UserDefaults.standard.string(forKey: "lastSync") ?? "لم تتم المزامنة بعد"

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: 14) {
                        Image(systemName: "shield.checkered").font(.system(size: 40)).foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("WOLVE").font(.title2.bold())
                            Text("يحميك من رسائل ومكالمات الاحتيال").foregroundStyle(.secondary)
                        }
                    }
                    LabeledContent("رسائل احتيال نُقلت إلى غير المرغوب", value: "\(SharedStore.junkCount)")
                    LabeledContent("تحذير المكالمات", value: callStatus)
                    LabeledContent("آخر مزامنة", value: lastSync)
                }
                Section("١. تصفية الرسائل") {
                    Text("الإعدادات ← التطبيقات ← الرسائل ← المرسلون المجهولون والبريد العشوائي ← تصفية الرسائل ← اختر WOLVE")
                    Text("تُفحص رسائل المرسلين غير الموجودين في جهات الاتصال فقط، على الجوال نفسه، وتُنقل رسائل الاحتيال إلى «غير مرغوب».")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("٢. تحذير المكالمات قبل الرد") {
                    Text("الإعدادات ← التطبيقات ← الهاتف ← حظر المكالمات وتحديد هويتها ← فعّل WOLVE")
                    Button("فتح إعدادات حظر المكالمات") {
                        CXCallDirectoryManager.sharedInstance.openSettings { _ in }
                    }
                    Text("يظهر تحذير تحت رقم المتصل للأرقام المُبلّغ عنها، أو يُحظر الرقم. التحذير مبني على الرقم فقط، ويمكن تزييف هوية المتصل.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section {
                    Button {
                        Task { await sync() }
                    } label: {
                        HStack { Text("مزامنة قوائم الحماية من WOLVE"); if syncing { Spacer(); ProgressView() } }
                    }.disabled(syncing)
                    if let message { Text(message).font(.footnote) }
                }
            }
            .navigationTitle("الحماية")
            .task { refreshCallStatus() }
        }
    }

    private func refreshCallStatus() {
        CXCallDirectoryManager.sharedInstance.getEnabledStatusForExtension(withIdentifier: SharedStore.callDirectoryExtensionID) { status, _ in
            DispatchQueue.main.async {
                switch status {
                case .enabled: callStatus = "مُفعَّل"
                case .disabled: callStatus = "غير مُفعَّل — فعّله من الإعدادات"
                default: callStatus = "غير معروف"
                }
            }
        }
    }

    private func sync() async {
        guard let url = URL(string: serverURL) else { message = "عنوان الخادم غير صحيح"; return }
        syncing = true
        defer { syncing = false }
        do {
            let result = try await WolveAPI(baseURL: url).syncProtection()
            try await CXCallDirectoryManager.sharedInstance.reloadExtension(withIdentifier: SharedStore.callDirectoryExtensionID)
            let stamp = Date().formatted(date: .abbreviated, time: .shortened)
            UserDefaults.standard.set(stamp, forKey: "lastSync")
            lastSync = stamp
            message = "تمت المزامنة: \(result.rules) عنصر محظور، \(result.numbers) رقم في قائمة التحذير."
            refreshCallStatus()
        } catch {
            message = error.localizedDescription
        }
    }
}

// MARK: - Manual checks (uses the WOLVE server, or offline rules if not connected)

struct CheckView: View {
    @AppStorage("serverURL") private var serverURL = AppConfig.defaultServer
    @State private var sender = ""
    @State private var text = ""
    @State private var number = ""
    @State private var busy = false
    @State private var smsResult: (score: Int, title: String, reasons: [String], junk: Bool, source: String)?
    @State private var callResult: CallerCheck?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("افحص رسالة") {
                    TextField("المرسل (رقم أو اسم أو بريد)", text: $sender).environment(\.layoutDirection, .leftToRight)
                    TextField("نص الرسالة", text: $text, axis: .vertical).lineLimit(3...8)
                    Button("افحص الرسالة") { Task { await checkMessage() } }.disabled(text.isEmpty || busy)
                    if let r = smsResult {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(r.junk ? "⚠️ \(r.title) — \(r.score)/100" : "✅ لم يُعثر على تهديد واضح — \(r.score)/100")
                                .font(.headline).foregroundStyle(r.junk ? .red : .green)
                            ForEach(r.reasons.prefix(4), id: \.self) { Text("• \($0)").font(.footnote) }
                            Text(r.source).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
                Section("افحص رقماً") {
                    TextField("+971 50 123 4567", text: $number).keyboardType(.phonePad).environment(\.layoutDirection, .leftToRight)
                    Button("افحص الرقم") { Task { await checkNumber() } }.disabled(number.isEmpty || busy)
                    if let c = callResult {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(c.warn ? c.label : "✅ لا توجد تحذيرات على هذا الرقم").font(.headline).foregroundStyle(c.level == "danger" ? .red : c.warn ? .orange : .green)
                            if let region = c.registered_region { Text("مسجّل لدى: \(region)").font(.footnote) }
                            ForEach(c.reasons, id: \.self) { Text("• \($0)").font(.footnote) }
                            if !c.advice.isEmpty { Text(c.advice).font(.footnote) }
                            Text(c.note).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
                if let error { Section { Text(error).foregroundStyle(.red) } }
            }
            .navigationTitle("افحص")
        }
    }

    private func checkMessage() async {
        busy = true; error = nil
        defer { busy = false }
        if let url = URL(string: serverURL), Keychain.load("deviceToken") != nil {
            do {
                let r = try await WolveAPI(baseURL: url).checkMessage(sender: sender, body: text)
                smsResult = (r.risk_score, r.classification, r.reasons, r.action == "junk", "تحليل خادم WOLVE")
                return
            } catch {
                self.error = error.localizedDescription + " — تم الفحص على الجوال بدلاً من ذلك."
            }
        }
        let v = ScamRules.evaluate(sender: sender, body: text, config: SharedStore.loadConfig())
        smsResult = (v.score, "احتيال محتمل", v.reasons, v.isJunk, "فحص على الجوال (بدون إنترنت)")
    }

    private func checkNumber() async {
        busy = true; error = nil
        defer { busy = false }
        guard let url = URL(string: serverURL) else { error = "عنوان الخادم غير صحيح"; return }
        do { callResult = try await WolveAPI(baseURL: url).checkCaller(number) } catch { self.error = error.localizedDescription }
    }
}

// MARK: - Pairing

struct SettingsView: View {
    @AppStorage("serverURL") private var serverURL = AppConfig.defaultServer
    @State private var code = ""
    @State private var consent = false
    @State private var paired = Keychain.load("deviceToken") != nil
    @State private var busy = false
    @State private var confirmDelete = false
    @State private var message: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("خادم WOLVE") {
                    TextField(AppConfig.defaultServer, text: $serverURL)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .environment(\.layoutDirection, .leftToRight)
                }
                Section("الخصوصية") {
                    Text("يفحص WOLVE رسائل المرسلين المجهولين على الجوال نفسه ولا يرفعها. لا يقرأ رسائل جهات الاتصال، ولا يستمع للمكالمات. عند الفحص اليدوي فقط يُرسل النص إلى خادم WOLVE.")
                        .font(.footnote)
                    Link("سياسة الخصوصية", destination: URL(string: serverURL + "/privacy") ?? URL(string: AppConfig.defaultServer)!)
                }
                if paired {
                    Section {
                        Label("الجوال مربوط بـ WOLVE", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                        Button("فك الربط وحذف بيانات هذا الجوال", role: .destructive) { confirmDelete = true }
                    }
                } else {
                    Section("ربط الجوال") {
                        TextField("رمز الربط (من WOLVE ← الإعدادات ← ربط جهاز)", text: $code)
                            .textInputAutocapitalization(.characters).autocorrectionDisabled()
                        Toggle("أوافق على حماية هذا الجوال", isOn: $consent)
                        Button("ربط الجوال") { Task { await pair() } }.disabled(!consent || busy || code.count < 6)
                    }
                }
                if let message { Section { Text(message).font(.footnote) } }
            }
            .navigationTitle("الإعدادات")
            .confirmationDialog("سيتم فك ربط الجوال وحذف بياناته من خادم WOLVE.", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("فك الربط والحذف", role: .destructive) { Task { await unpair() } }
                Button("إلغاء", role: .cancel) {}
            }
        }
    }

    private func pair() async {
        guard let url = URL(string: serverURL) else { message = "عنوان الخادم غير صحيح"; return }
        busy = true
        defer { busy = false }
        do {
            try await WolveAPI(baseURL: url).register(pairingCode: code, deviceName: UIDevice.current.name)
            paired = true
            code = ""
            message = "تم الربط. اذهب إلى «الحماية» واضغط مزامنة."
        } catch {
            message = error.localizedDescription
        }
    }

    private func unpair() async {
        guard let url = URL(string: serverURL) else { return }
        busy = true
        defer { busy = false }
        do {
            try await WolveAPI(baseURL: url).deleteDevice()
            message = "تم فك الربط وحذف بيانات الجوال من الخادم."
        } catch {
            Keychain.delete("deviceToken")
            message = "تم فك الربط على الجوال، لكن تعذّر الوصول للخادم: \(error.localizedDescription)"
        }
        try? SharedStore.saveDirectory([])
        paired = false
    }
}
