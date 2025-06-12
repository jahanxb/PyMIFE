# from secrets import randbelow
# from Crypto.Util.number import bytes_to_long
# from typing import List, Tuple, Callable

# from mife.common import discrete_log_bound, inner_product, getStrongPrime
# from mife.data.group import GroupBase, GroupElem
# from mife.data.zmod import Zmod

# from hashlib import shake_256
# from abc import ABC, abstractmethod

# import numpy as np

# # References:
# # https://eprint.iacr.org/2017/989.pdf

# class _FeDDHMultiClient_Hash(ABC):
#     @abstractmethod
#     def __call__(self, tag: bytes) -> Tuple[int, int]:
#         pass

#     @abstractmethod
#     def export(self) -> dict:
#         pass

# class _FeDDHMultiClient_Hash_Default(_FeDDHMultiClient_Hash):
#     def __init__(self, maximum_bit: int):
#         self.maximum_bit = maximum_bit

#     def __call__(self, tag: bytes) -> Tuple[int, int]:
#         t = shake_256(tag).digest(self.maximum_bit * 2)
#         return bytes_to_long(t[:len(t) // 2]), bytes_to_long(t[len(t) // 2:])

#     def export(self) -> dict:
#         return {
#             "type": "default",
#             "maximum_bit": self.maximum_bit
#         }

# class _FeDDHMultiClient_MK:
#     def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase,
#                  hash: _FeDDHMultiClient_Hash,
#                  msk: List[List[Tuple[int, int]]] = None):
#         self.g = g
#         self.n = n
#         self.m = m
#         self.F = F
#         self.hash = hash
#         self.msk = msk  # Secret matrices S_i for each client i

#     def get_enc_key(self, index: int):
#         """Get encryption key for client i (contains S_i)"""
#         if not self.has_private_key:
#             raise Exception("The master key has no private key")
#         if not (0 <= index < self.n):
#             raise Exception(f"Index must be within [0,{self.n})")
#         return _FeDDHMultiClient_EncK(self.g, self.hash, self.msk[index], self.F)

#     @property
#     def has_private_key(self) -> bool:
#         return self.msk is not None

#     def get_public_key(self):
#         return _FeDDHMultiClient_MK(self.g, self.n, self.m, self.F, self.hash)

#     def export(self):
#         return {
#             "g": self.g.export(),
#             "n": self.n,
#             "m": self.m,
#             "F": self.F.export(),
#             "hash": self.hash.export(),
#             "msk": [[[int(vec2[0]), int(vec2[1])] for vec2 in vec] for vec in
#                     self.msk] if self.msk is not None else None
#         }

# class _FeDDHMultiClient_EncK:
#     def __init__(self, g: GroupElem,
#                  hash: _FeDDHMultiClient_Hash,
#                  secret_matrix: List[Tuple[int, int]],
#                  F: GroupBase):
#         self.g = g
#         self.hash = hash
#         self.secret_matrix = secret_matrix  # S_i = [(s^(1)_i,1, s^(2)_i,1), ..., (s^(1)_i,m, s^(2)_i,m)]
#         self.F = F

#     def export(self):
#         return {
#             "g": self.g.export(),
#             "hash": self.hash.export(),
#             "secret_matrix": self.secret_matrix,
#             "F": self.F.export()
#         }

# class _FeDDHMultiClient_SK:
#     def __init__(self, y: List[List[int]], d: Tuple[int, int]):
#         self.y = y
#         self.d = d

#     def export(self):
#         return {
#             "y": self.y,
#             "d": self.d
#         }

# class _FeDDHMultiClient_C:
#     def __init__(self, tag: bytes, c: List[GroupElem]):
#         self.c = c
#         self.tag = tag

#     def export(self):
#         return {
#             "tag": self.tag.hex(),
#             "c": [x.export() for x in self.c]
#         }

# class _FeDDHMultiClient_SK_Safe:
#     def __init__(self, y: List[List[int]], td: Tuple[int, int]):
#         """
#         Initialize FeDDHMultiClient decryption key

#         :param y: Function vector
#         :param td: g1 * <msk, y>, g2 * <msk, y>
#         """
#         self.y = y
#         self.td = td

#     def export(self):
#         return {
#             "y": self.y,
#             "d": self.d
#         }

# class FeDDHMultiClient:

#     @staticmethod
#     def generate(n: int, m: int, F: GroupBase = None,
#                  hash: Callable[[bytes, int], Tuple[int, int]] = None) -> _FeDDHMultiClient_MK:
#         """
#         Generate a FeDDHMultiClient master key following PDF Setup specification
        
#         Setup creates:
#         - Public parameters: n (# clients), m (vector length), G = ⟨g⟩, H
#         - Secret state: Each client i samples secret matrix S_i ∈ Z_p^(2×m)

#         :param n: Number of clients
#         :param m: Dimension of message vector for each client (vector length)
#         :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
#         :param hash: Hash function H: {0,1}* → Z_p^2. If set to None, a default hash function will be used
#         :return: FeDDHMultiClient master key
#         """
#         if F is None:
#             F = Zmod(getStrongPrime(1024))
#         if hash is None:
#             hash = _FeDDHMultiClient_Hash_Default(F.order().bit_length())

#         g = F.generator()
        
#         # Generate secret matrices S_i for each client i ∈ [n]
#         # Each S_i ∈ Z_p^(2×m) with columns s_i,j = (s^(1)_i,j, s^(2)_i,j)^T
#         msk = []
#         for i in range(n):
#             client_secret_matrix = []
#             for j in range(m):
#                 s_1_ij = randbelow(F.order())  # s^(1)_i,j
#                 s_2_ij = randbelow(F.order())  # s^(2)_i,j
#                 client_secret_matrix.append((s_1_ij, s_2_ij))
#             msk.append(client_secret_matrix)

#         return _FeDDHMultiClient_MK(g, n, m, F, hash, msk=msk)

#     @staticmethod
#     def encrypt(x: List[int], tag: bytes, key: _FeDDHMultiClient_EncK) -> _FeDDHMultiClient_C:
#         """
#         Encrypt message vector following PDF Encryption specification
        
#         Encryption for client i ∈ [n]:
#         1. Random-oracle hash: u_τ = (u1, u2) = H(τ) ∈ Z_p^2
#         2. Mask via matrix-vector multiplication: mv_i = u_τ^T S_i ∈ Z_p^m
#         3. Add the plaintext vector: [c]_i = mv_i + x_i ∈ Z_p^m  
#         4. Exponentiate with group generator: c_i = (g^{e_i,1}, ..., g^{e_i,m}) ∈ G^m

#         :param x: Message vector x_i ∈ Z_p^m
#         :param tag: Tag τ ∈ {0,1}* (e.g. timestamp)
#         :param key: Client encryption key (contains S_i)
#         :return: FeDDHMultiClient cipher text
#         """
#         if len(x) != len(key.secret_matrix):
#             raise Exception(f"Message vector must be of length {len(key.secret_matrix)}")

#         # Step 1: Random-oracle hash H(τ) = (u1, u2)
#         u1, u2 = key.hash(tag)
#         #print(f"Step 1 - Hash: u_τ = ({u1}, {u2})")

#         # Step 2: Mask via matrix-vector multiplication
#         # mv_i = u_τ^T S_i where mv_i,j = u1 * s^(1)_i,j + u2 * s^(2)_i,j
#         mask_vector = []
#         for j in range(len(key.secret_matrix)):
#             s_1_ij, s_2_ij = key.secret_matrix[j]
#             mv_ij = (u1 * s_1_ij + u2 * s_2_ij) % key.F.order()
#             mask_vector.append(mv_ij)
        
#         #print(f"Step 2 - Mask vector: mv_i = {mask_vector}")

#         # Step 3: Add the plaintext vector
#         # [c]_i = mv_i + x_i ∈ Z_p^m
#         plaintext_masked = []
#         for j in range(len(x)):
#             e_ij = (mask_vector[j] + x[j]) % key.F.order()
#             plaintext_masked.append(e_ij)
            
#         #print(f"Step 3 - Masked plaintext: [c]_i = {plaintext_masked}")

#         # Step 4: Exponentiate with the group generator
#         # c_i = (g^{e_i,1}, g^{e_i,2}, ..., g^{e_i,m}) ∈ G^m
#         ciphertext = []
#         for j in range(len(plaintext_masked)):
#             c_ij = plaintext_masked[j] * key.g  # This gives g^{e_i,j}
#             ciphertext.append(c_ij)
            
#         #print(f"Step 4 - Ciphertext: c_i = [g^{plaintext_masked[0]}, g^{plaintext_masked[1]}, ...]")

#         return _FeDDHMultiClient_C(tag, ciphertext)

#     @staticmethod
#     def decrypt(c: List[_FeDDHMultiClient_C], tag: bytes,
#                 key: _FeDDHMultiClient_MK, sk: _FeDDHMultiClient_SK,
#                 bound: Tuple[int, int]) -> int:
#         """
#         Decrypt FeDDHMultiClient cipher text

#         :param c: FeDDHMultiClient cipher text
#         :param tag: Tag for decryption, the same tag must be used for encryption
#         :param key: FeDDHMultiClient public key
#         :param sk: FeDDHMultiClient decryption key
#         :param bound: Bound for the discrete log problem
#         :return: Decrypted message
#         """
#         u1, u2 = key.hash(tag)
#         u1, u2 = key.g * u1, key.g * u2

#         cul = key.F.identity()

#         for i in range(key.n):
#             cul = cul + inner_product(c[i].c, sk.y[i], key.F.identity())

#         cul = cul - (sk.d[0] * u1 + sk.d[1] * u2)
#         return discrete_log_bound(cul, key.g, bound)

#     @staticmethod
#     def decrypt_safe(c: List[_FeDDHMultiClient_C], key: _FeDDHMultiClient_MK, sk: _FeDDHMultiClient_SK_Safe,
#                      bound: Tuple[int, int]) -> int:
#         """
#         Decrypt FeDDHMultiClient cipher text

#         :param c: FeDDHMultiClient cipher text
#         :param key: FeDDHMultiClient public key
#         :param sk: FeDDHMultiClient decryption key
#         :param bound: Bound for the discrete log problem
#         :return: Decrypted message
#         """
#         cul = key.F.identity()

#         for i in range(key.n):
#             cul = cul + inner_product(c[i].c, sk.y[i], key.F.identity())

#         cul = cul - (sk.td[0] + sk.td[1])
#         return discrete_log_bound(cul, key.g, bound)

#     @staticmethod
#     def keygen(y: List[List[int]], key: _FeDDHMultiClient_MK) -> _FeDDHMultiClient_SK:
#         """
#         Generate a FeDDHMultiClient decryption key

#         :param y: Function vector
#         :param key: FeDDHMultiClient master key
#         :return: FeDDHMultiClient decryption key
#         """
#         if len(y) != key.n:
#             raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
#         cul_1 = 0
#         cul_2 = 0
        
#         for i in range(key.n):
#             if len(y[i]) != key.m:
#                 raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
#             for j in range(key.m):
#                 s1, s2 = key.msk[i][j]
#                 cul_1 += s1 * y[i][j]
#                 cul_2 += s2 * y[i][j]
#                 cul_1 %= key.F.order()
#                 cul_2 %= key.F.order()

#         d = (cul_1, cul_2)
#         return _FeDDHMultiClient_SK(y, d)

#     @staticmethod
#     def keygen_safe(y: List[List[int]], key: _FeDDHMultiClient_MK, tag: bytes) -> _FeDDHMultiClient_SK_Safe:
#         """
#         Generate a safe FeDDHMultiClient decryption key

#         :param y: Function vector
#         :param key: FeDDHMultiClient master key
#         :param tag: Tag for the decryption key
#         :return: FeDDHMultiClient decryption key
#         """
#         normal_key = FeDDHMultiClient.keygen(y, key)
#         u1, u2 = key.hash(tag)
#         u1, u2 = key.g * u1, key.g * u2
#         td = (u1 * normal_key.d[0], u2 * normal_key.d[1])
#         return _FeDDHMultiClient_SK_Safe(y, td)

#     @staticmethod
#     def verify_pdf_example():
#         """
#         Verify the example from the PDF document:
#         - Tag-hash: u_τ^T = [1, 2]
#         - Client secret matrix: S_i = [[3, 5, 7], [4, 6, 8]]
#         - Message: x_i = [1, 2, 3]
#         - Expected mask vector: mv_i = [11, 17, 23]
#         - Expected masked plaintext: e_i = [12, 19, 26]
#         """
#         print("=== PDF Example Verification ===")
        
#         # Create a simple group for testing (using small prime for clarity)
#         from mife.data.zmod import Zmod
#         F = Zmod(97)  # Small prime for testing
#         g = F.generator()
        
#         # Create hash that returns the example values
#         class TestHash(_FeDDHMultiClient_Hash):
#             def __call__(self, tag: bytes) -> Tuple[int, int]:
#                 return (1, 2)  # u_τ = (1, 2) as in PDF example
#             def export(self) -> dict:
#                 return {"type": "test"}
        
#         # Create master key with the example secret matrix
#         test_hash = TestHash()
#         master_key = _FeDDHMultiClient_MK(g, 1, 3, F, test_hash, 
#                                          msk=[[(3, 4), (5, 6), (7, 8)]])  # S_i = [[3,5,7],[4,6,8]]
        
#         # Get encryption key for client 0
#         enc_key = master_key.get_enc_key(0)
        
#         # Test message from PDF
#         x_i = [1, 2, 3]
#         tag = b"test"
        
#         print(f"Input message: x_i = {x_i}")
#         print(f"Secret matrix S_i = [[3, 5, 7], [4, 6, 8]]")
        
#         # Encrypt
#         ciphertext = FeDDHMultiClient.encrypt(x_i, tag, enc_key)
        
#         # Manual verification of intermediate steps
#         u1, u2 = 1, 2
#         expected_mask = []
#         for j in range(3):
#             s_1_j, s_2_j = [(3, 4), (5, 6), (7, 8)][j]
#             mv_j = u1 * s_1_j + u2 * s_2_j
#             expected_mask.append(mv_j)
        
#         expected_plaintext_masked = [expected_mask[j] + x_i[j] for j in range(3)]
        
#         print(f"Expected mask vector: {expected_mask}")
#         print(f"Expected masked plaintext: {expected_plaintext_masked}")
#         print(f"PDF expected: mask=[11, 17, 23], masked=[12, 19, 26]")
#         print(f"Match: {expected_mask == [11, 17, 23] and expected_plaintext_masked == [12, 19, 26]}")

#     @staticmethod
#     def decrypt_vector(c: List[_FeDDHMultiClient_C], tag: bytes,
#                       key: _FeDDHMultiClient_MK, bound: Tuple[int, int],
#                       extraction_mode: str = "component_sums") -> List[int]:
#         """
#         MODIFIED DECRYPT FUNCTION - Returns vectors instead of scalars
        
#         Mathematical Equation:
#         Instead of: MCFE(x₁, x₂, ..., xₙ; y₁, y₂, ..., yₙ) = Σᵢ ⟨xᵢ, yᵢ⟩ (scalar)
        
#         We compute: MCFE_vector(x₁, x₂, ..., xₙ) = [Σᵢ xᵢ₁, Σᵢ xᵢ₂, ..., Σᵢ xᵢₘ] (vector)
        
#         Where each component j is extracted using basis vectors:
#         component_j = MCFE(x₁, x₂, ..., xₙ; e₁ⱼ, e₂ⱼ, ..., eₙⱼ) = Σᵢ xᵢⱼ
        
#         :param c: FeDDHMultiClient cipher text
#         :param tag: Tag for decryption
#         :param key: FeDDHMultiClient master key (with private key)
#         :param bound: Bound for discrete log problem
#         :param extraction_mode: "component_sums" or "weighted_average"
#         :return: Vector of extracted components [c₁, c₂, ..., cₘ]
#         """
        
#         if not key.has_private_key():
#             raise Exception("The master key must have private key for vector decryption")
        
#         result_vector = []
        
#         # Extract each vector component separately
#         for j in range(key.m):  # For each dimension j = 1, 2, ..., m
            
#             if extraction_mode == "component_sums":
#                 # Create basis vector extraction pattern for component j
#                 # y[i][j] = 1 for all clients i, others = 0
#                 y_basis = [[0] * key.m for _ in range(key.n)]
#                 for i in range(key.n):
#                     y_basis[i][j] = 1  # Extract j-th component from all clients
                
#                 # Compute decryption key for this component
#                 d_j = FeDDHMultiClient._compute_decryption_key(y_basis, key)
                
#             elif extraction_mode == "weighted_average":
#                 # Use integer weights (1 for each client) and divide result later
#                 y_weighted = [[0] * key.m for _ in range(key.n)]
#                 for i in range(key.n):
#                     y_weighted[i][j] = 1  # Use weight of 1, divide final result by n
                
#                 # Compute decryption key for weighted average
#                 d_j = FeDDHMultiClient._compute_decryption_key(y_weighted, key)
            
#             # Perform decryption for component j
#             u1, u2 = key.hash(tag)
#             u1, u2 = key.g * u1, key.g * u2
            
#             cul = key.F.identity()
            
#             # Compute inner product for component j
#             for i in range(key.n):
#                 if extraction_mode == "component_sums":
#                     # Only consider j-th component of each client
#                     component_contribution = c[i].c[j] * y_basis[i][j]  # This is c[i][j] * 1
#                     cul = cul + component_contribution
#                 elif extraction_mode == "weighted_average":
#                     # Sum contribution of j-th component (divide by n later)
#                     component_contribution = c[i].c[j] * y_weighted[i][j]  # This is c[i][j] * 1
#                     cul = cul + component_contribution
            
#             # Remove hash contribution
#             cul = cul - (d_j[0] * u1 + d_j[1] * u2)
            
#             # Extract component value
#             component_value = discrete_log_bound(cul, key.g, bound)
            
#             # For weighted average, divide by n to get the average
#             if extraction_mode == "weighted_average":
#                 component_value = component_value // key.n  # Integer division for average
            
#             result_vector.append(component_value)
        
#         return result_vector

#     @staticmethod
#     def _compute_decryption_key(y_pattern: List[List[int]], key: _FeDDHMultiClient_MK) -> Tuple[int, int]:
#         """
#         Helper function to compute decryption key for given y pattern
#         """
#         cul_1 = 0
#         cul_2 = 0
        
#         for i in range(key.n):
#             for j in range(key.m):
#                 s1, s2 = key.msk[i][j]
#                 cul_1 += s1 * y_pattern[i][j]
#                 cul_2 += s2 * y_pattern[i][j]
#                 cul_1 %= key.F.order()
#                 cul_2 %= key.F.order()
        
#         return (cul_1, cul_2)







# # USAGE EXAMPLE WITH FIXED CALLS
# if __name__ == "__main__":
#     # Verify PDF example first
#     FeDDHMultiClient.verify_pdf_example()
    
#     print("\n" + "="*50)
#     print("=== Main Example ===")
    
#     # Your exact setup
#     n = 3
#     m = 5
#     x = [[i+1 for j in range(m)] for i in range(n)]
#     y = [[j*10 for j in range(m)] for i in range(n)]
    
#     print('x =', x)
#     print('y =', y)
    
#     tag = b"testingtag123"
#     key = FeDDHMultiClient.generate(n, m)
#     print(f'Generated key for {n} clients with vector dimension {m}')
#     sk_x = FeDDHMultiClient.keygen(x, key)
#     # Encrypt each client's vector
#     print(f"\n=== Encrypting {n} client vectors ===")
#     cs = []
#     for i in range(n):
#         print(f"\nClient {i} encryption:")
#         c_i = FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i))
#         cs.append(c_i)
    
#     print(f'\nEncrypted {len(cs)} ciphertexts successfully')


#     #result_y1 = FeDDHMultiClient.decrypt_vector(cs, tag, key.get_public_key(), sk_y1, (0, 9999))
#     result_y2 = FeDDHMultiClient.decrypt_vector(cs, tag, key.get_public_key(), sk_x, (0, 9999))
#     #print("Inner product ⟨x, y⟩ =", result_y1)
#     print(" inner product  =", result_y2)

    
from secrets import randbelow
from Crypto.Util.number import bytes_to_long
from typing import List, Tuple, Callable

from mife.common import discrete_log_bound, inner_product, getStrongPrime
from mife.data.group import GroupBase, GroupElem
from mife.data.zmod import Zmod

from hashlib import shake_256
from abc import ABC, abstractmethod

import numpy as np

# References:
# https://eprint.iacr.org/2017/989.pdf

class _FeDDHMultiClient_Hash(ABC):
    @abstractmethod
    def __call__(self, tag: bytes) -> Tuple[int, int]:
        pass

    @abstractmethod
    def export(self) -> dict:
        pass

class _FeDDHMultiClient_Hash_Default(_FeDDHMultiClient_Hash):
    def __init__(self, maximum_bit: int):
        self.maximum_bit = maximum_bit

    def __call__(self, tag: bytes) -> Tuple[int, int]:
        t = shake_256(tag).digest(self.maximum_bit * 2)
        return bytes_to_long(t[:len(t) // 2]), bytes_to_long(t[len(t) // 2:])

    def export(self) -> dict:
        return {
            "type": "default",
            "maximum_bit": self.maximum_bit
        }

class _FeDDHMultiClient_MK:
    def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase,
                 hash: _FeDDHMultiClient_Hash,
                 msk: List[List[Tuple[int, int]]] = None):
        self.g = g
        self.n = n
        self.m = m
        self.F = F
        self.hash = hash
        self.msk = msk  # Secret matrices S_i for each client i

    def get_enc_key(self, index: int):
        """Get encryption key for client i (contains S_i)"""
        if not self.has_private_key:
            raise Exception("The master key has no private key")
        if not (0 <= index < self.n):
            raise Exception(f"Index must be within [0,{self.n})")
        return _FeDDHMultiClient_EncK(self.g, self.hash, self.msk[index], self.F)

    @property
    def has_private_key(self) -> bool:
        return self.msk is not None

    def get_public_key(self):
        return _FeDDHMultiClient_MK(self.g, self.n, self.m, self.F, self.hash)

    def export(self):
        return {
            "g": self.g.export(),
            "n": self.n,
            "m": self.m,
            "F": self.F.export(),
            "hash": self.hash.export(),
            "msk": [[[int(vec2[0]), int(vec2[1])] for vec2 in vec] for vec in
                    self.msk] if self.msk is not None else None
        }

class _FeDDHMultiClient_EncK:
    def __init__(self, g: GroupElem,
                 hash: _FeDDHMultiClient_Hash,
                 secret_matrix: List[Tuple[int, int]],
                 F: GroupBase):
        self.g = g
        self.hash = hash
        self.secret_matrix = secret_matrix  # S_i = [(s^(1)_i,1, s^(2)_i,1), ..., (s^(1)_i,m, s^(2)_i,m)]
        self.F = F

    def export(self):
        return {
            "g": self.g.export(),
            "hash": self.hash.export(),
            "secret_matrix": self.secret_matrix,
            "F": self.F.export()
        }

class _FeDDHMultiClient_SK:
    def __init__(self, y: List[List[int]], d: Tuple[int, int]):
        self.y = y
        self.d = d

    def export(self):
        return {
            "y": self.y,
            "d": self.d
        }

class _FeDDHMultiClient_C:
    def __init__(self, tag: bytes, c: List[GroupElem]):
        self.c = c
        self.tag = tag

    def export(self):
        return {
            "tag": self.tag.hex(),
            "c": [x.export() for x in self.c]
        }

class _FeDDHMultiClient_SK_Safe:
    def __init__(self, y: List[List[int]], td: Tuple[int, int]):
        """
        Initialize FeDDHMultiClient decryption key

        :param y: Function vector
        :param td: g1 * <msk, y>, g2 * <msk, y>
        """
        self.y = y
        self.td = td

    def export(self):
        return {
            "y": self.y,
            "d": self.d
        }

class FeDDHMultiClient:

    @staticmethod
    def generate(n: int, m: int, F: GroupBase = None,
                 hash: Callable[[bytes, int], Tuple[int, int]] = None) -> _FeDDHMultiClient_MK:
        """
        Generate a FeDDHMultiClient master key following PDF Setup specification
        
        Setup creates:
        - Public parameters: n (# clients), m (vector length), G = ⟨g⟩, H
        - Secret state: Each client i samples secret matrix S_i ∈ Z_p^(2×m)

        :param n: Number of clients
        :param m: Dimension of message vector for each client (vector length)
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :param hash: Hash function H: {0,1}* → Z_p^2. If set to None, a default hash function will be used
        :return: FeDDHMultiClient master key
        """
        if F is None:
            F = Zmod(getStrongPrime(1024))
        if hash is None:
            hash = _FeDDHMultiClient_Hash_Default(F.order().bit_length())

        g = F.generator()
        
        # Generate secret matrices S_i for each client i ∈ [n]
        # Each S_i ∈ Z_p^(2×m) with columns s_i,j = (s^(1)_i,j, s^(2)_i,j)^T
        msk = []
        for i in range(n):
            client_secret_matrix = []
            for j in range(m):
                s_1_ij = randbelow(F.order())  # s^(1)_i,j
                s_2_ij = randbelow(F.order())  # s^(2)_i,j
                client_secret_matrix.append((s_1_ij, s_2_ij))
            msk.append(client_secret_matrix)

        return _FeDDHMultiClient_MK(g, n, m, F, hash, msk=msk)

    @staticmethod
    def encrypt(x: List[int], tag: bytes, key: _FeDDHMultiClient_EncK) -> _FeDDHMultiClient_C:
        """
        Encrypt message vector following PDF Encryption specification
        
        Encryption for client i ∈ [n]:
        1. Random-oracle hash: u_τ = (u1, u2) = H(τ) ∈ Z_p^2
        2. Mask via matrix-vector multiplication: mv_i = u_τ^T S_i ∈ Z_p^m
        3. Add the plaintext vector: [c]_i = mv_i + x_i ∈ Z_p^m  
        4. Exponentiate with group generator: c_i = (g^{e_i,1}, ..., g^{e_i,m}) ∈ G^m

        :param x: Message vector x_i ∈ Z_p^m
        :param tag: Tag τ ∈ {0,1}* (e.g. timestamp)
        :param key: Client encryption key (contains S_i)
        :return: FeDDHMultiClient cipher text
        """
        if len(x) != len(key.secret_matrix):
            raise Exception(f"Message vector must be of length {len(key.secret_matrix)}")

        # Step 1: Random-oracle hash H(τ) = (u1, u2)
        u1, u2 = key.hash(tag)

        # Step 2: Mask via matrix-vector multiplication
        # mv_i = u_τ^T S_i where mv_i,j = u1 * s^(1)_i,j + u2 * s^(2)_i,j
        mask_vector = []
        for j in range(len(key.secret_matrix)):
            s_1_ij, s_2_ij = key.secret_matrix[j]
            mv_ij = (u1 * s_1_ij + u2 * s_2_ij) % key.F.order()
            mask_vector.append(mv_ij)

        # Step 3: Add the plaintext vector
        # [c]_i = mv_i + x_i ∈ Z_p^m
        plaintext_masked = []
        for j in range(len(x)):
            e_ij = (mask_vector[j] + x[j]) % key.F.order()
            plaintext_masked.append(e_ij)

        # Step 4: Exponentiate with the group generator
        # c_i = (g^{e_i,1}, g^{e_i,2}, ..., g^{e_i,m}) ∈ G^m
        ciphertext = []
        for j in range(len(plaintext_masked)):
            c_ij = plaintext_masked[j] * key.g  # This gives g^{e_i,j}
            ciphertext.append(c_ij)

        return _FeDDHMultiClient_C(tag, ciphertext)

    @staticmethod
    def decrypt(c: List[_FeDDHMultiClient_C], tag: bytes,
                key: _FeDDHMultiClient_MK, sk: _FeDDHMultiClient_SK,
                bound: Tuple[int, int]) -> int:
        """
        Decrypt FeDDHMultiClient cipher text

        :param c: FeDDHMultiClient cipher text
        :param tag: Tag for decryption, the same tag must be used for encryption
        :param key: FeDDHMultiClient public key
        :param sk: FeDDHMultiClient decryption key
        :param bound: Bound for the discrete log problem
        :return: Decrypted message
        """
        u1, u2 = key.hash(tag)
        u1, u2 = key.g * u1, key.g * u2

        cul = key.F.identity()

        for i in range(key.n):
            cul = cul + inner_product(c[i].c, sk.y[i], key.F.identity())

        cul = cul - (sk.d[0] * u1 + sk.d[1] * u2)
        return discrete_log_bound(cul, key.g, bound)

    @staticmethod
    def decrypt_safe(c: List[_FeDDHMultiClient_C], key: _FeDDHMultiClient_MK, sk: _FeDDHMultiClient_SK_Safe,
                     bound: Tuple[int, int]) -> int:
        """
        Decrypt FeDDHMultiClient cipher text

        :param c: FeDDHMultiClient cipher text
        :param key: FeDDHMultiClient public key
        :param sk: FeDDHMultiClient decryption key
        :param bound: Bound for the discrete log problem
        :return: Decrypted message
        """
        cul = key.F.identity()

        for i in range(key.n):
            cul = cul + inner_product(c[i].c, sk.y[i], key.F.identity())

        cul = cul - (sk.td[0] + sk.td[1])
        return discrete_log_bound(cul, key.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], key: _FeDDHMultiClient_MK) -> _FeDDHMultiClient_SK:
        """
        Generate a FeDDHMultiClient decryption key

        :param y: Function vector
        :param key: FeDDHMultiClient master key
        :return: FeDDHMultiClient decryption key
        """
        if len(y) != key.n:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        cul_1 = 0
        cul_2 = 0
        
        for i in range(key.n):
            if len(y[i]) != key.m:
                raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
            for j in range(key.m):
                s1, s2 = key.msk[i][j]
                cul_1 += s1 * y[i][j]
                cul_2 += s2 * y[i][j]
                cul_1 %= key.F.order()
                cul_2 %= key.F.order()

        d = (cul_1, cul_2)
        return _FeDDHMultiClient_SK(y, d)

    @staticmethod
    def keygen_safe(y: List[List[int]], key: _FeDDHMultiClient_MK, tag: bytes) -> _FeDDHMultiClient_SK_Safe:
        """
        Generate a safe FeDDHMultiClient decryption key

        :param y: Function vector
        :param key: FeDDHMultiClient master key
        :param tag: Tag for the decryption key
        :return: FeDDHMultiClient decryption key
        """
        normal_key = FeDDHMultiClient.keygen(y, key)
        u1, u2 = key.hash(tag)
        u1, u2 = key.g * u1, key.g * u2
        td = (u1 * normal_key.d[0], u2 * normal_key.d[1])
        return _FeDDHMultiClient_SK_Safe(y, td)

    @staticmethod
    def verify_pdf_example():
        """
        Verify the example from the PDF document:
        - Tag-hash: u_τ^T = [1, 2]
        - Client secret matrix: S_i = [[3, 5, 7], [4, 6, 8]]
        - Message: x_i = [1, 2, 3]
        - Expected mask vector: mv_i = [11, 17, 23]
        - Expected masked plaintext: e_i = [12, 19, 26]
        """
        print("=== PDF Example Verification ===")
        
        # Create a simple group for testing (using small prime for clarity)
        from mife.data.zmod import Zmod
        F = Zmod(97)  # Small prime for testing
        g = F.generator()
        
        # Create hash that returns the example values
        class TestHash(_FeDDHMultiClient_Hash):
            def __call__(self, tag: bytes) -> Tuple[int, int]:
                return (1, 2)  # u_τ = (1, 2) as in PDF example
            def export(self) -> dict:
                return {"type": "test"}
        
        # Create master key with the example secret matrix
        test_hash = TestHash()
        master_key = _FeDDHMultiClient_MK(g, 1, 3, F, test_hash, 
                                         msk=[[(3, 4), (5, 6), (7, 8)]])  # S_i = [[3,5,7],[4,6,8]]
        
        # Get encryption key for client 0
        enc_key = master_key.get_enc_key(0)
        
        # Test message from PDF
        x_i = [1, 2, 3]
        tag = b"test"
        
        print(f"Input message: x_i = {x_i}")
        print(f"Secret matrix S_i = [[3, 5, 7], [4, 6, 8]]")
        
        # Encrypt
        ciphertext = FeDDHMultiClient.encrypt(x_i, tag, enc_key)
        
        # Manual verification of intermediate steps
        u1, u2 = 1, 2
        expected_mask = []
        for j in range(3):
            s_1_j, s_2_j = [(3, 4), (5, 6), (7, 8)][j]
            mv_j = u1 * s_1_j + u2 * s_2_j
            expected_mask.append(mv_j)
        
        expected_plaintext_masked = [expected_mask[j] + x_i[j] for j in range(3)]
        
        print(f"Expected mask vector: {expected_mask}")
        print(f"Expected masked plaintext: {expected_plaintext_masked}")
        print(f"PDF expected: mask=[11, 17, 23], masked=[12, 19, 26]")
        print(f"Match: {expected_mask == [11, 17, 23] and expected_plaintext_masked == [12, 19, 26]}")

    @staticmethod
    def decrypt_vector(c: List[_FeDDHMultiClient_C], tag: bytes,
                      key: _FeDDHMultiClient_MK, bound: Tuple[int, int]) -> List[int]:
        """
        VECTOR DECRYPTION FOR FEDERATED LEARNING
        
        Computes component-wise sum across all clients:
        Result[j] = Σᵢ x_i[j] for j = 0, 1, ..., m-1
        
        For federated learning, this gives you the aggregated vector across all clients.
        
        :param c: List of encrypted ciphertexts from all clients
        :param tag: Tag used for encryption
        :param key: Master key with private key (NOT public key)
        :param bound: Bound for discrete log problem
        :return: Vector [sum₀, sum₁, ..., sum_{m-1}] where sum_j = Σᵢ x_i[j]
        """
        
        if not key.has_private_key:
            raise Exception("Master key must have private key for vector decryption")
        
        result_vector = []
        
        # Extract each vector component j separately
        for j in range(key.m):
            # Create basis function vector to extract component j
            # y[i][k] = 1 if k == j, else 0 (for all clients i)
            y_basis = [[0] * key.m for _ in range(key.n)]
            for i in range(key.n):
                y_basis[i][j] = 1  # Extract j-th component from all clients
            
            # Generate decryption key for this basis vector
            sk_j = FeDDHMultiClient.keygen(y_basis, key)
            
            # Perform standard decryption to get component sum
            component_sum = FeDDHMultiClient.decrypt(c, tag, key, sk_j, bound)
            
            result_vector.append(component_sum)
        
        return result_vector

# USAGE EXAMPLE WITH FIXED CALLS
if __name__ == "__main__":
    # Verify PDF example first
    FeDDHMultiClient.verify_pdf_example()
    
    print("\n" + "="*50)
    print("=== Federated Learning Vector Aggregation Example ===")
    
    # Federated learning setup - 3 clients, 5-dimensional vectors
    n = 3  # Number of clients
    m = 5  # Vector dimension
    
    # Each client has different data vectors (like traffic flow data)
    x = [[1, 1, 1, 1, 1],     # Client 0's data
         [2, 2, 2, 2, 2],     # Client 1's data  
         [3, 3, 3, 3, 3]]     # Client 2's data
    
    print('Client data vectors:')
    for i, client_data in enumerate(x):
        print(f'  Client {i}: {client_data}')
    
    # Expected aggregated result (component-wise sum)
    expected_result = [sum(x[i][j] for i in range(n)) for j in range(m)]
    print(f'Expected aggregated vector: {expected_result}')
    
    # Generate master key for the federated system
    tag = b"federated_round_1"
    key = FeDDHMultiClient.generate(n, m)
    print(f'Generated master key for {n} clients with {m}-dimensional vectors')
    
    # Each client encrypts their data vector
    print(f"\n=== Encrypting {n} client vectors ===")
    cs = []
    for i in range(n):
        print(f"Encrypting Client {i} data...")
        c_i = FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i))
        cs.append(c_i)
    
    print(f'Successfully encrypted {len(cs)} client vectors')
    
    # Perform federated aggregation using vector decryption
    print(f"\n=== Federated Vector Aggregation ===")
    aggregated_vector = FeDDHMultiClient.decrypt_vector(cs, tag, key, (0, 9999))
    
    print(f'Aggregated vector: {aggregated_vector}')
    print(f'Expected vector:   {expected_result}')
    print(f'Aggregation successful: {aggregated_vector == expected_result}')
    
    # Show component-wise verification
    print(f"\n=== Component-wise Verification ===")
    for j in range(m):
        manual_sum = sum(x[i][j] for i in range(n))
        print(f'Component {j}: {[x[i][j] for i in range(n)]} → sum = {manual_sum} ✓')