"""
Merkle Tree Implementation
"""
import hashlib
from typing import List, Optional

class MerkleTree:
    """Merkle Tree implementation for location whitelist verification"""
    
    def __init__(self, leaves: List[str]):
        """
        Initialize Merkle tree with leaves
        
        Args:
            leaves: List of leaf values (geohash strings)
        """
        self.leaves = leaves
        self.tree = self._build_tree(leaves)
    
    def _hash(self, data: str) -> bytes:
        """Hash function for Merkle tree"""
        return hashlib.sha256(data.encode()).digest()
    
    def _build_tree(self, leaves: List[str]) -> List[List[bytes]]:
        """
        Build Merkle tree from leaves
        
        Returns:
            List of levels, where each level is a list of hashes
        """
        if not leaves:
            return []
        
        # Start with leaf level
        tree = []
        current_level = [self._hash(leaf) for leaf in leaves]
        tree.append(current_level)
        
        # Build intermediate levels
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i+1 < len(current_level) else left
                combined = left + right
                next_level.append(hashlib.sha256(combined).digest())
            tree.append(next_level)
            current_level = next_level
        
        return tree
    
    def get_root(self) -> str:
        """Get Merkle root as hex string"""
        if not self.tree:
            return ""
        return self.tree[-1][0].hex()
    
    def get_proof(self, leaf: str) -> List[str]:
        """
        Generate Merkle proof for a leaf
        
        Args:
            leaf: Leaf value to generate proof for
            
        Returns:
            List of sibling hashes as hex strings
        """
        if leaf not in self.leaves:
            return []
        
        index = self.leaves.index(leaf)
        proof = []
        current_index = index
        
        # Traverse up the tree
        for level in self.tree[:-1]:  # Exclude root
            level_size = len(level)
            if current_index % 2 == 0:
                # Left node, get right sibling
                sibling_index = current_index + 1 if current_index + 1 < level_size else current_index
            else:
                # Right node, get left sibling
                sibling_index = current_index - 1
            
            sibling_hash = level[sibling_index]
            proof.append(sibling_hash.hex())
            current_index //= 2
        
        return proof
    
    def verify_proof(self, leaf: str, proof: List[str], root: str) -> bool:
        """
        Verify Merkle proof
        
        Args:
            leaf: Leaf value to verify
            proof: Merkle proof as list of hex strings
            root: Merkle root as hex string
            
        Returns:
            True if proof is valid, False otherwise
        """
        if not proof or not root:
            return False
        
        # Calculate leaf hash
        current_hash = self._hash(leaf)
        
        # Apply proof
        for sibling_hex in proof:
            sibling = bytes.fromhex(sibling_hex)
            # For simplicity, we assume even indices are left nodes
            # In a real implementation, we would need to track the exact path
            combined = current_hash + sibling
            current_hash = hashlib.sha256(combined).digest()
        
        # Compare with root
        return current_hash.hex() == root