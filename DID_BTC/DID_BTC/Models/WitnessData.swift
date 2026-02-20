// WitnessData.swift - Merkle Witness for Membership Proofs
// SignedByMe iOS

import Foundation

/// Merkle witness data for membership proofs.
/// Fetched from API after enrollment.
struct WitnessData: Codable {
    
    // MARK: - Properties
    
    /// Root ID (identifies the Merkle tree version)
    let rootId: String
    
    /// Merkle root hash (32 bytes hex)
    let root: String
    
    /// Sibling hashes in path from leaf to root (20 siblings, each 32 bytes hex)
    let siblings: [String]
    
    /// Path indices: 0 = sibling is on left, 1 = sibling is on right
    let pathIndices: [Int]
    
    /// Leaf index in the tree
    let leafIndex: Int
    
    /// Timestamp when witness was fetched
    let fetchedAt: Date
    
    // MARK: - Coding Keys
    
    enum CodingKeys: String, CodingKey {
        case rootId = "root_id"
        case root
        case siblings
        case pathIndices = "path_indices"
        case leafIndex = "leaf_index"
        case fetchedAt = "fetched_at"
    }
    
    // MARK: - Computed Properties
    
    /// Tree depth (should be 20 for SignedByMe)
    var depth: Int {
        siblings.count
    }
    
    /// Check if witness is valid format
    var isValid: Bool {
        guard siblings.count == 20,
              pathIndices.count == 20,
              root.count == 64 else {
            return false
        }
        
        // Validate all siblings are 64 hex chars
        for sibling in siblings {
            guard sibling.count == 64 else { return false }
        }
        
        return true
    }
    
    // MARK: - Initialization
    
    init(rootId: String, root: String, siblings: [String], pathIndices: [Int], leafIndex: Int, fetchedAt: Date = Date()) {
        self.rootId = rootId
        self.root = root
        self.siblings = siblings
        self.pathIndices = pathIndices
        self.leafIndex = leafIndex
        self.fetchedAt = fetchedAt
    }
    
    /// Initialize from API response
    init?(json: [String: Any]) {
        guard let rootId = json["root_id"] as? String,
              let root = json["root"] as? String,
              let siblings = json["siblings"] as? [String],
              let pathIndices = json["path_indices"] as? [Int],
              let leafIndex = json["leaf_index"] as? Int else {
            return nil
        }
        
        self.rootId = rootId
        self.root = root
        self.siblings = siblings
        self.pathIndices = pathIndices
        self.leafIndex = leafIndex
        self.fetchedAt = Date()
    }
}

// MARK: - Sample Data

extension WitnessData {
    /// Sample witness for previews
    static var sample: WitnessData {
        WitnessData(
            rootId: "root-sample-123",
            root: String(repeating: "a", count: 64),
            siblings: (0..<20).map { _ in String(repeating: "b", count: 64) },
            pathIndices: (0..<20).map { _ in Int.random(in: 0...1) },
            leafIndex: 42
        )
    }
}
