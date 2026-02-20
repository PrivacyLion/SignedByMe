// EnrollmentData.swift - Membership Enrollment Response
// SignedByMe iOS

import Foundation

/// Response from membership enrollment API
struct EnrollmentResponse: Codable {
    let status: String
    let leafIndex: Int
    let message: String?
    
    enum CodingKeys: String, CodingKey {
        case status
        case leafIndex = "leaf_index"
        case message
    }
    
    var isSuccess: Bool {
        status == "enrolled" || status == "already_enrolled" || status == "success"
    }
}

/// Request body for membership enrollment
struct EnrollmentRequest: Codable {
    let leafCommitment: String
    let didPubkey: String
    
    enum CodingKeys: String, CodingKey {
        case leafCommitment = "leaf_commitment"
        case didPubkey = "did_pubkey"
    }
}

/// Login invoice submission request
struct LoginInvoiceRequest: Codable {
    let sessionToken: String
    let stwoProof: String
    let invoice: String
    let membershipProof: String?
    
    enum CodingKeys: String, CodingKey {
        case sessionToken = "session_token"
        case stwoProof = "stwo_proof"
        case invoice
        case membershipProof = "membership_proof"
    }
}

/// Login invoice submission response
struct LoginInvoiceResponse: Codable {
    let status: String
    let sessionId: String?
    let paymentHash: String?
    let message: String?
    let error: String?
    
    enum CodingKeys: String, CodingKey {
        case status
        case sessionId = "session_id"
        case paymentHash = "payment_hash"
        case message
        case error
    }
    
    var isSuccess: Bool {
        status == "pending" || status == "success"
    }
}

/// Session poll response
struct SessionPollResponse: Codable {
    let status: String
    let paid: Bool?
    let idToken: String?
    let satsEarned: Int64?
    let error: String?
    
    enum CodingKeys: String, CodingKey {
        case status
        case paid
        case idToken = "id_token"
        case satsEarned = "sats_earned"
        case error
    }
    
    var isPaid: Bool {
        paid == true || status == "paid" || status == "complete"
    }
}

/// Wallet transaction model
struct WalletTransaction: Codable, Identifiable {
    let id: String
    let type: TransactionType
    let amountSats: Int64
    let timestamp: Date
    let description: String?
    let paymentHash: String?
    let preimage: String?
    let status: TransactionStatus
    
    enum TransactionType: String, Codable {
        case receive
        case send
    }
    
    enum TransactionStatus: String, Codable {
        case pending
        case complete
        case failed
    }
    
    enum CodingKeys: String, CodingKey {
        case id
        case type
        case amountSats = "amount_sats"
        case timestamp
        case description
        case paymentHash = "payment_hash"
        case preimage
        case status
    }
}
