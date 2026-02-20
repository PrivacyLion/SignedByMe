// LoginSession.swift - Login Session from QR/Deep Link
// SignedByMe iOS

import Foundation

/// Represents a login session parsed from QR code or deep link.
/// Maps to session data from the SignedByMe API.
struct LoginSession: Codable, Identifiable {
    
    // MARK: - Properties
    
    /// Unique session identifier
    let sessionId: String
    
    /// Enterprise client ID
    let clientId: String
    
    /// Enterprise domain (e.g., "acmecorp.com")
    let domain: String
    
    /// Enterprise display name (e.g., "Acme Corp")
    let displayName: String
    
    /// Payment amount in satoshis
    let amountSats: Int64
    
    /// Session nonce (16 bytes hex = 32 chars) for replay protection
    let nonce: String
    
    /// Session expiry timestamp (Unix)
    let expiresAt: Int64?
    
    /// Whether membership proof is required
    let requireMembership: Bool
    
    /// Required root ID (if membership required)
    let requiredRootId: String?
    
    /// OIDC state parameter (if present)
    let state: String?
    
    /// OIDC redirect URI
    let redirectUri: String?
    
    /// JWT from session token (raw)
    let rawToken: String?
    
    // MARK: - Identifiable
    
    var id: String { sessionId }
    
    // MARK: - Coding Keys
    
    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case clientId = "client_id"
        case domain
        case displayName = "display_name"
        case amountSats = "amount_sats"
        case nonce
        case expiresAt = "expires_at"
        case requireMembership = "require_membership"
        case requiredRootId = "required_root_id"
        case state
        case redirectUri = "redirect_uri"
        case rawToken = "raw_token"
    }
    
    // MARK: - Initialization
    
    /// Initialize from deep link URL
    init?(deepLink: URL) {
        guard let components = URLComponents(url: deepLink, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            return nil
        }
        
        // Extract query parameters
        var params: [String: String] = [:]
        for item in queryItems {
            if let value = item.value {
                params[item.name] = value
            }
        }
        
        // Required parameters
        guard let sessionId = params["session"] ?? params["session_id"],
              let clientId = params["client_id"] ?? params["client"],
              let domain = params["domain"] ?? params["employer"],
              let amountStr = params["amount"] ?? params["amount_sats"],
              let amount = Int64(amountStr),
              let nonce = params["nonce"] else {
            return nil
        }
        
        self.sessionId = sessionId
        self.clientId = clientId
        self.domain = domain
        self.displayName = params["display_name"] ?? params["name"] ?? domain
        self.amountSats = amount
        self.nonce = nonce
        
        // Optional parameters
        if let expiresStr = params["expires_at"] ?? params["exp"] {
            self.expiresAt = Int64(expiresStr)
        } else {
            self.expiresAt = nil
        }
        
        self.requireMembership = params["require_membership"] == "true" || params["require_membership"] == "1"
        self.requiredRootId = params["required_root_id"] ?? params["root_id"]
        self.state = params["state"]
        self.redirectUri = params["redirect_uri"]
        self.rawToken = params["token"]
    }
    
    /// Initialize from JWT token
    init?(jwt: String) {
        // Decode JWT payload (middle part)
        let parts = jwt.split(separator: ".")
        guard parts.count == 3 else { return nil }
        
        var base64 = String(parts[1])
        // Pad base64 if needed
        while base64.count % 4 != 0 {
            base64 += "="
        }
        
        guard let data = Data(base64Encoded: base64),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        
        // Extract claims
        guard let sessionId = json["session_id"] as? String ?? json["jti"] as? String,
              let clientId = json["client_id"] as? String ?? json["aud"] as? String,
              let domain = json["domain"] as? String ?? json["iss"] as? String else {
            return nil
        }
        
        self.sessionId = sessionId
        self.clientId = clientId
        self.domain = domain
        self.displayName = json["display_name"] as? String ?? domain
        self.amountSats = (json["amount_sats"] as? Int64) ?? (json["amount"] as? Int64) ?? 500
        self.nonce = json["nonce"] as? String ?? UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(32).lowercased()
        self.expiresAt = json["exp"] as? Int64
        self.requireMembership = json["require_membership"] as? Bool ?? false
        self.requiredRootId = json["required_root_id"] as? String
        self.state = json["state"] as? String
        self.redirectUri = json["redirect_uri"] as? String
        self.rawToken = jwt
    }
    
    // MARK: - Computed Properties
    
    /// Check if session is expired
    var isExpired: Bool {
        guard let expiresAt = expiresAt else { return false }
        return Int64(Date().timeIntervalSince1970) > expiresAt
    }
    
    /// Time until expiry in seconds
    var timeUntilExpiry: TimeInterval? {
        guard let expiresAt = expiresAt else { return nil }
        return TimeInterval(expiresAt) - Date().timeIntervalSince1970
    }
    
    /// Formatted expiry string
    var expiryDescription: String {
        guard let seconds = timeUntilExpiry else { return "No expiry" }
        if seconds <= 0 { return "Expired" }
        if seconds < 60 { return "\(Int(seconds))s" }
        if seconds < 3600 { return "\(Int(seconds / 60))m" }
        return "\(Int(seconds / 3600))h"
    }
}

// MARK: - Sample Data

extension LoginSession {
    /// Sample session for previews
    static var sample: LoginSession {
        LoginSession(
            sessionId: "test-session-123",
            clientId: "acme",
            domain: "acmecorp.com",
            displayName: "Acme Corp",
            amountSats: 500,
            nonce: "0123456789abcdef0123456789abcdef",
            expiresAt: Int64(Date().timeIntervalSince1970 + 600),
            requireMembership: true,
            requiredRootId: "root-abc123",
            state: nil,
            redirectUri: nil,
            rawToken: nil
        )
    }
    
    // Full memberwise initializer
    init(
        sessionId: String,
        clientId: String,
        domain: String,
        displayName: String,
        amountSats: Int64,
        nonce: String,
        expiresAt: Int64?,
        requireMembership: Bool,
        requiredRootId: String?,
        state: String?,
        redirectUri: String?,
        rawToken: String?
    ) {
        self.sessionId = sessionId
        self.clientId = clientId
        self.domain = domain
        self.displayName = displayName
        self.amountSats = amountSats
        self.nonce = nonce
        self.expiresAt = expiresAt
        self.requireMembership = requireMembership
        self.requiredRootId = requiredRootId
        self.state = state
        self.redirectUri = redirectUri
        self.rawToken = rawToken
    }
}
