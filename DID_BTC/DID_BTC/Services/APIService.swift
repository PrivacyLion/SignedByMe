// APIService.swift - SignedByMe API Client
// SignedByMe iOS

import Foundation

/// API client for SignedByMe backend
actor APIService {
    
    // MARK: - Singleton
    
    static let shared = APIService()
    
    // MARK: - Configuration
    
    #if DEBUG
    private let baseURL = "https://api.beta.privacy-lion.com"
    #else
    private let baseURL = "https://api.signedby.me"
    #endif
    
    private let session: URLSession
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    
    // MARK: - Initialization
    
    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        self.session = URLSession(configuration: config)
        
        encoder.keyEncodingStrategy = .convertToSnakeCase
        decoder.keyDecodingStrategy = .convertFromSnakeCase
    }
    
    // MARK: - Membership Enrollment
    
    /// Enroll for membership (auto-enroll in Step 3)
    func enrollMembership(leafCommitment: Data, didPubkey: String) async throws -> EnrollmentResponse {
        let url = URL(string: "\(baseURL)/v1/membership/enroll")!
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body: [String: Any] = [
            "leaf_commitment": leafCommitment.hexString,
            "did_pubkey": didPubkey
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        
        return try decoder.decode(EnrollmentResponse.self, from: data)
    }
    
    /// Fetch witness data after enrollment
    func fetchWitness(leafCommitment: Data) async throws -> WitnessData {
        let commitmentHex = leafCommitment.hexString
        let url = URL(string: "\(baseURL)/v1/membership/witness/\(commitmentHex)")!
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        
        return try decoder.decode(WitnessData.self, from: data)
    }
    
    // MARK: - Login Flow
    
    /// Submit login invoice with STWO proof
    func submitLoginInvoice(
        sessionToken: String,
        stwoProof: String,
        invoice: String,
        membershipProof: Data?
    ) async throws -> LoginInvoiceResponse {
        let url = URL(string: "\(baseURL)/v1/login/invoice")!
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        var body: [String: Any] = [
            "session_token": sessionToken,
            "stwo_proof": stwoProof,
            "invoice": invoice
        ]
        
        if let membershipProof = membershipProof {
            body["membership_proof"] = membershipProof.base64EncodedString()
        }
        
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        
        return try decoder.decode(LoginInvoiceResponse.self, from: data)
    }
    
    /// Poll session for payment status
    func pollSession(sessionId: String) async throws -> SessionPollResponse {
        let url = URL(string: "\(baseURL)/v1/session/\(sessionId)/status")!
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        
        return try decoder.decode(SessionPollResponse.self, from: data)
    }
    
    /// Poll session with retry until paid or timeout
    func waitForPayment(sessionId: String, timeoutSeconds: Int = 120) async throws -> SessionPollResponse {
        let startTime = Date()
        let pollInterval: UInt64 = 2_000_000_000 // 2 seconds in nanoseconds
        
        while Date().timeIntervalSince(startTime) < TimeInterval(timeoutSeconds) {
            let response = try await pollSession(sessionId: sessionId)
            
            if response.isPaid {
                return response
            }
            
            if let error = response.error {
                throw APIError.serverError(error)
            }
            
            // Wait before next poll
            try await Task.sleep(nanoseconds: pollInterval)
        }
        
        throw APIError.timeout
    }
    
    // MARK: - Roots (Merkle Tree)
    
    /// Get current root info
    func getCurrentRoot() async throws -> RootInfo {
        let url = URL(string: "\(baseURL)/v1/roots/current")!
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, response) = try await session.data(for: request)
        try validateResponse(response)
        
        return try decoder.decode(RootInfo.self, from: data)
    }
    
    // MARK: - Price Feed
    
    /// Get current BTC price in USD
    func getBtcPrice() async throws -> Double {
        let url = URL(string: "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd")!
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, _) = try await session.data(for: request)
        
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let bitcoin = json["bitcoin"] as? [String: Any],
              let price = bitcoin["usd"] as? Double else {
            throw APIError.invalidResponse
        }
        
        return price
    }
    
    // MARK: - Helpers
    
    private func validateResponse(_ response: URLResponse) throws {
        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }
        
        switch httpResponse.statusCode {
        case 200...299:
            return
        case 400:
            throw APIError.badRequest
        case 401:
            throw APIError.unauthorized
        case 404:
            throw APIError.notFound
        case 429:
            throw APIError.rateLimited
        case 500...599:
            throw APIError.serverError("HTTP \(httpResponse.statusCode)")
        default:
            throw APIError.httpError(httpResponse.statusCode)
        }
    }
}

// MARK: - API Errors

enum APIError: Error, LocalizedError {
    case invalidResponse
    case badRequest
    case unauthorized
    case notFound
    case rateLimited
    case serverError(String)
    case httpError(Int)
    case timeout
    case noData
    
    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "Invalid response from server"
        case .badRequest: return "Bad request"
        case .unauthorized: return "Unauthorized"
        case .notFound: return "Not found"
        case .rateLimited: return "Rate limited - please try again later"
        case .serverError(let msg): return "Server error: \(msg)"
        case .httpError(let code): return "HTTP error \(code)"
        case .timeout: return "Request timed out"
        case .noData: return "No data received"
        }
    }
}

// MARK: - Supporting Models

struct RootInfo: Codable {
    let rootId: String
    let root: String
    let leafCount: Int
    let createdAt: String
    
    enum CodingKeys: String, CodingKey {
        case rootId = "root_id"
        case root
        case leafCount = "leaf_count"
        case createdAt = "created_at"
    }
}
