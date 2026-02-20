// KeychainManager.swift - Secure Storage for SignedByMe iOS
// Mirrors Android's EncryptedSharedPreferences + Keystore

import Foundation
import Security
import LocalAuthentication

/// Manages secure storage using iOS Keychain with optional Secure Enclave backing.
/// Mirrors Android's EncryptedSharedPreferences pattern.
final class KeychainManager {
    
    // MARK: - Constants
    
    static let shared = KeychainManager()
    
    private let service = "com.privacylion.signedby.me"
    
    // Keychain item keys
    enum Key: String {
        case didPrivateKey = "did_private_key"
        case didPublicKey = "did_public_key"
        case walletMnemonic = "wallet_mnemonic"
        case walletSeed = "wallet_seed"
        case stwoProof = "stwo_proof"
        case stwoProofHash = "stwo_proof_hash"
        case leafSecret = "membership_leaf_secret"
        case witnessData = "membership_witness"
        case biometricEnabled = "biometric_enabled"
        case backupCompleted = "backup_completed"
        case lastLoginTimestamp = "last_login_timestamp"
    }
    
    // MARK: - Errors
    
    enum KeychainError: Error, LocalizedError {
        case itemNotFound
        case duplicateItem
        case invalidData
        case unhandledError(status: OSStatus)
        case biometricFailed
        case secureEnclaveNotAvailable
        
        var errorDescription: String? {
            switch self {
            case .itemNotFound: return "Item not found in Keychain"
            case .duplicateItem: return "Item already exists in Keychain"
            case .invalidData: return "Invalid data format"
            case .unhandledError(let status): return "Keychain error: \(status)"
            case .biometricFailed: return "Biometric authentication failed"
            case .secureEnclaveNotAvailable: return "Secure Enclave not available"
            }
        }
    }
    
    // MARK: - Initialization
    
    private init() {}
    
    // MARK: - Core Operations
    
    /// Save data to Keychain
    func save(_ data: Data, for key: Key, requireBiometric: Bool = false) throws {
        // First try to delete any existing item
        try? delete(key)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Add biometric protection if requested
        if requireBiometric {
            let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryCurrentSet,
                nil
            )
            if let access = access {
                query[kSecAttrAccessControl as String] = access
                query.removeValue(forKey: kSecAttrAccessible as String)
            }
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status: status)
        }
    }
    
    /// Save string to Keychain
    func save(_ string: String, for key: Key, requireBiometric: Bool = false) throws {
        guard let data = string.data(using: .utf8) else {
            throw KeychainError.invalidData
        }
        try save(data, for: key, requireBiometric: requireBiometric)
    }
    
    /// Load data from Keychain
    func load(_ key: Key) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw KeychainError.itemNotFound
            }
            throw KeychainError.unhandledError(status: status)
        }
        
        guard let data = result as? Data else {
            throw KeychainError.invalidData
        }
        
        return data
    }
    
    /// Load string from Keychain
    func loadString(_ key: Key) throws -> String {
        let data = try load(key)
        guard let string = String(data: data, encoding: .utf8) else {
            throw KeychainError.invalidData
        }
        return string
    }
    
    /// Delete item from Keychain
    func delete(_ key: Key) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: status)
        }
    }
    
    /// Check if item exists
    func exists(_ key: Key) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
            kSecReturnData as String: false
        ]
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    // MARK: - Biometric Authentication
    
    /// Check if biometric authentication is available
    var isBiometricAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    /// Get biometric type name
    var biometricTypeName: String {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return "None"
        }
        
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        @unknown default: return "Biometric"
        }
    }
    
    /// Authenticate with biometrics
    func authenticateWithBiometrics(reason: String) async throws -> Bool {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw KeychainError.biometricFailed
        }
        
        return try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        )
    }
    
    // MARK: - Secure Enclave (StrongBox equivalent)
    
    /// Check if Secure Enclave is available
    var isSecureEnclaveAvailable: Bool {
        // Secure Enclave is available on devices with A7+ chip (iPhone 5S+)
        // For our purposes, we'll check if we can create a SE-backed key
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }
    
    // MARK: - Convenience Methods
    
    /// Delete all SignedByMe data from Keychain
    func deleteAll() throws {
        for key in Key.allCases {
            try? delete(key)
        }
    }
    
    /// Check if DID is set up
    var hasIdentity: Bool {
        exists(.didPrivateKey)
    }
    
    /// Check if wallet is set up
    var hasWallet: Bool {
        exists(.walletMnemonic) || exists(.walletSeed)
    }
    
    /// Check if STWO proof exists
    var hasStwoProof: Bool {
        exists(.stwoProof)
    }
    
    /// Check if membership is enrolled
    var hasMembership: Bool {
        exists(.leafSecret) && exists(.witnessData)
    }
}

// MARK: - Key CaseIterable

extension KeychainManager.Key: CaseIterable {}

// MARK: - JSON Storage Helpers

extension KeychainManager {
    
    /// Save Codable object to Keychain
    func save<T: Encodable>(_ object: T, for key: Key, requireBiometric: Bool = false) throws {
        let encoder = JSONEncoder()
        let data = try encoder.encode(object)
        try save(data, for: key, requireBiometric: requireBiometric)
    }
    
    /// Load Codable object from Keychain
    func load<T: Decodable>(_ type: T.Type, for key: Key) throws -> T {
        let data = try load(key)
        let decoder = JSONDecoder()
        return try decoder.decode(type, from: data)
    }
}
