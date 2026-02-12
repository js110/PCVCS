import hashlib
from typing import List, Optional

class MerkleTree:
    
    def __init__(self, leaves: List[str]):
        self.leaves = leaves
        self.tree = self._build_tree(leaves)
    
    def _hash(self, data: str) -> bytes:
        return hashlib.sha256(data.encode()).digest()
    
    def _build_tree(self, leaves: List[str]) -> List[List[bytes]]:
        if not leaves:
            return []
        
                               
        tree = []
        current_level = [self._hash(leaf) for leaf in leaves]
        tree.append(current_level)
        
                                   
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
        if not self.tree:
            return ""
        return self.tree[-1][0].hex()
    
    def get_proof(self, leaf: str) -> List[str]:
        if leaf not in self.leaves:
            return []
        
        index = self.leaves.index(leaf)
        proof = []
        current_index = index
        
                              
        for level in self.tree[:-1]:                
            level_size = len(level)
            if current_index % 2 == 0:
                                              
                sibling_index = current_index + 1 if current_index + 1 < level_size else current_index
            else:
                                              
                sibling_index = current_index - 1
            
            sibling_hash = level[sibling_index]
            proof.append(sibling_hash.hex())
            current_index //= 2
        
        return proof
    
    def verify_proof(self, leaf: str, proof: List[str], root: str) -> bool:
        if not proof or not root:
            return False
        
                             
        current_hash = self._hash(leaf)
        
                     
        for sibling_hex in proof:
            sibling = bytes.fromhex(sibling_hex)
                                                                   
                                                                             
            combined = current_hash + sibling
            current_hash = hashlib.sha256(combined).digest()
        
                           
        return current_hash.hex() == root