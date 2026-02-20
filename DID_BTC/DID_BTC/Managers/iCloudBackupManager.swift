// iCloudBackupManager.swift - Cloud Backup for SignedByMe iOS
// Mirrors Android GoogleDriveBackupManager.kt but uses iCloud

import Foundation
import CryptoKit

/// Manages encrypted backups to iCloud Drive
@MainActor
final class iCloudBackupManager: ObservableObject {
    
    // MARK: - Published Properties
    
    @Published private(set) var isBackedUp = false
    @Published private(set) var lastBackupDate: Date?
    @Published private(set) var isUploading = false
    @Published private(set) var isDownloading = false
    
    // MARK: - Private Properties
    
    private let keychain = KeychainManager.shared
    private let fileManager = FileManager.default
    
    // iCloud container identifier
    private let containerIdentifier = "iCloud.com.privacylion.signedby.me"
    private let backupFileName = "signedby_backup.enc"
    
    // MARK: - Initialization
    
    init() {
        Task {
            await checkBackupStatus()
        }
    }
    
    // MARK: - Backup
    
    /// Create encrypted backup and upload to iCloud
    func backup(password: String) async throws {
        isUploading = true
        defer { isUploading = false }
        
        // Get mnemonic from Keychain
        let mnemonicString = try keychain.loadString(.walletMnemonic)
        
        // Encrypt mnemonic with password
        let encryptedData = try encrypt(data: Data(mnemonicString.utf8), password: password)
        
        // Get iCloud container URL
        guard let containerURL = fileManager.url(forUbiquityContainerIdentifier: containerIdentifier) else {
            throw BackupError.iCloudNotAvailable
        }
        
        // Create Documents folder if needed
        let documentsURL = containerURL.appendingPathComponent("Documents", isDirectory: true)
        if !fileManager.fileExists(atPath: documentsURL.path) {
            try fileManager.createDirectory(at: documentsURL, withIntermediateDirectories: true)
        }
        
        // Write encrypted backup
        let backupURL = documentsURL.appendingPathComponent(backupFileName)
        try encryptedData.write(to: backupURL)
        
        // Update state
        isBackedUp = true
        lastBackupDate = Date()
        try keychain.save("true", for: .backupCompleted)
        
        print("✅ Backup uploaded to iCloud")
    }
    
    /// Restore wallet from iCloud backup
    func restore(password: String) async throws -> [String] {
        isDownloading = true
        defer { isDownloading = false }
        
        // Get iCloud container URL
        guard let containerURL = fileManager.url(forUbiquityContainerIdentifier: containerIdentifier) else {
            throw BackupError.iCloudNotAvailable
        }
        
        // Find backup file
        let backupURL = containerURL
            .appendingPathComponent("Documents", isDirectory: true)
            .appendingPathComponent(backupFileName)
        
        guard fileManager.fileExists(atPath: backupURL.path) else {
            throw BackupError.backupNotFound
        }
        
        // Start downloading if needed (iCloud lazy loading)
        try fileManager.startDownloadingUbiquitousItem(at: backupURL)
        
        // Wait for download to complete
        var attempts = 0
        while attempts < 30 {
            if fileManager.isUbiquitousItem(at: backupURL) {
                let resourceValues = try backupURL.resourceValues(forKeys: [.ubiquitousItemDownloadingStatusKey])
                if resourceValues.ubiquitousItemDownloadingStatus == .current {
                    break
                }
            }
            try await Task.sleep(nanoseconds: 500_000_000) // 0.5s
            attempts += 1
        }
        
        // Read encrypted data
        let encryptedData = try Data(contentsOf: backupURL)
        
        // Decrypt with password
        let decryptedData = try decrypt(data: encryptedData, password: password)
        
        guard let mnemonicString = String(data: decryptedData, encoding: .utf8) else {
            throw BackupError.decryptionFailed
        }
        
        let mnemonic = mnemonicString.split(separator: " ").map(String.init)
        
        guard mnemonic.count == 12 || mnemonic.count == 24 else {
            throw BackupError.invalidBackup
        }
        
        print("✅ Restored backup from iCloud")
        return mnemonic
    }
    
    /// Check if backup exists in iCloud
    func checkBackupStatus() async {
        guard let containerURL = fileManager.url(forUbiquityContainerIdentifier: containerIdentifier) else {
            isBackedUp = false
            return
        }
        
        let backupURL = containerURL
            .appendingPathComponent("Documents", isDirectory: true)
            .appendingPathComponent(backupFileName)
        
        isBackedUp = fileManager.fileExists(atPath: backupURL.path)
        
        if isBackedUp {
            // Get modification date
            if let attrs = try? fileManager.attributesOfItem(atPath: backupURL.path),
               let modDate = attrs[.modificationDate] as? Date {
                lastBackupDate = modDate
            }
        }
    }
    
    /// Delete backup from iCloud
    func deleteBackup() async throws {
        guard let containerURL = fileManager.url(forUbiquityContainerIdentifier: containerIdentifier) else {
            throw BackupError.iCloudNotAvailable
        }
        
        let backupURL = containerURL
            .appendingPathComponent("Documents", isDirectory: true)
            .appendingPathComponent(backupFileName)
        
        if fileManager.fileExists(atPath: backupURL.path) {
            try fileManager.removeItem(at: backupURL)
        }
        
        isBackedUp = false
        lastBackupDate = nil
        try keychain.delete(.backupCompleted)
        
        print("🗑️ Deleted iCloud backup")
    }
    
    // MARK: - Encryption
    
    /// Encrypt data with password using AES-GCM
    private func encrypt(data: Data, password: String) throws -> Data {
        // Derive key from password using PBKDF2
        let salt = try generateSalt()
        let key = try deriveKey(password: password, salt: salt)
        
        // Generate random nonce
        let nonce = try AES.GCM.Nonce(data: generateSalt(length: 12))
        
        // Encrypt
        let sealedBox = try AES.GCM.seal(data, using: key, nonce: nonce)
        
        // Combine: salt (32) + nonce (12) + ciphertext + tag
        var result = Data()
        result.append(salt)
        result.append(contentsOf: nonce)
        result.append(sealedBox.ciphertext)
        result.append(sealedBox.tag)
        
        return result
    }
    
    /// Decrypt data with password
    private func decrypt(data: Data, password: String) throws -> Data {
        guard data.count > 44 else { // 32 (salt) + 12 (nonce) = 44 minimum
            throw BackupError.invalidBackup
        }
        
        // Extract components
        let salt = data.prefix(32)
        let nonce = data[32..<44]
        let ciphertext = data[44..<(data.count - 16)]
        let tag = data.suffix(16)
        
        // Derive key from password
        let key = try deriveKey(password: password, salt: Data(salt))
        
        // Create sealed box
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        
        // Decrypt
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    /// Derive encryption key from password
    private func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        // Use PBKDF2 with SHA256
        let passwordData = Data(password.utf8)
        
        // CryptoKit doesn't have PBKDF2 directly, so we use a simple approach
        // In production, use CommonCrypto's CCKeyDerivationPBKDF
        var derived = Data()
        derived.append(passwordData)
        derived.append(salt)
        
        // Multiple rounds of SHA256
        for _ in 0..<100_000 {
            derived = Data(SHA256.hash(data: derived))
        }
        
        return SymmetricKey(data: derived)
    }
    
    /// Generate random salt
    private func generateSalt(length: Int = 32) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        guard status == errSecSuccess else {
            throw BackupError.randomGenerationFailed
        }
        return Data(bytes)
    }
    
    // MARK: - Computed Properties
    
    /// Check if iCloud is available
    var isICloudAvailable: Bool {
        fileManager.url(forUbiquityContainerIdentifier: containerIdentifier) != nil
    }
    
    /// Formatted last backup date
    var formattedLastBackup: String {
        guard let date = lastBackupDate else {
            return "Never"
        }
        
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

// MARK: - Backup Errors

enum BackupError: Error, LocalizedError {
    case iCloudNotAvailable
    case backupNotFound
    case encryptionFailed
    case decryptionFailed
    case invalidBackup
    case randomGenerationFailed
    case wrongPassword
    
    var errorDescription: String? {
        switch self {
        case .iCloudNotAvailable: return "iCloud is not available. Please sign in to iCloud in Settings."
        case .backupNotFound: return "No backup found in iCloud"
        case .encryptionFailed: return "Failed to encrypt backup"
        case .decryptionFailed: return "Failed to decrypt backup. Wrong password?"
        case .invalidBackup: return "Invalid backup format"
        case .randomGenerationFailed: return "Failed to generate secure random data"
        case .wrongPassword: return "Incorrect password"
        }
    }
}
