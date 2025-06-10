from secrets import randbelow
from Crypto.Util.number import bytes_to_long
from typing import List, Tuple, Callable

from mife.common import discrete_log_bound, inner_product, getStrongPrime
from mife.data.group import GroupBase, GroupElem
from mife.data.zmod import Zmod

from hashlib import shake_256
from abc import ABC, abstractmethod

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
        self.msk = msk

    def get_enc_key(self, index: int):
        if not self.has_private_key:
            raise Exception("The master key has no private key")
        if not (0 <= index < self.n):
            raise Exception(f"Index must be within [0,{self.n})")
        return _FeDDHMultiClient_EncK(self.g, self.hash, self.msk[index])

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
                 enc_key: List[Tuple[int, int]]):
        self.g = g
        self.hash = hash
        self.enc_key = enc_key

    def export(self):
        return {
            "g": self.g.export(),
            "hash": self.hash.export(),
            "enc_key": self.enc_key
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

class FeDDHMultiClient:

    @staticmethod
    def generate(n: int, m: int, F: GroupBase = None,
                 hash: Callable[[bytes, int], Tuple[int, int]] = None) -> _FeDDHMultiClient_MK:
        if F is None:
            F = Zmod(getStrongPrime(1024))
        if hash is None:
            hash = _FeDDHMultiClient_Hash_Default(F.order().bit_length())

        g = F.generator()
        s = [[(randbelow(F.order()), randbelow(F.order())) for _ in range(m)] for _ in range(n)]

        return _FeDDHMultiClient_MK(g, n, m, F, hash, msk=s)

    @staticmethod
    def encrypt(x: List[int], tag: bytes, key: _FeDDHMultiClient_EncK) -> _FeDDHMultiClient_C:
        if len(x) != len(key.enc_key):
            raise Exception(f"Encrypt vector must be of length {len(key.enc_key)}")

        u1, u2 = key.hash(tag)
        c = []

        print("u1: ",u1)
        print("u2: ",u2)
        print("x: ",x)
        for i in range(len(x)):
            s1, s2 = key.enc_key[i]
            print("x[i]: ",x[i])
            cut = (u1 * s1 + u2 * s2 + x[i]) * key.g
            print("cu:",cut)
            c.append((u1 * s1 + u2 * s2 + x[i]) * key.g)
            

        return _FeDDHMultiClient_C(tag, c)

    @staticmethod
    def decrypt_vector(c: List[_FeDDHMultiClient_C], tag: bytes,
                      key: _FeDDHMultiClient_MK, bound: Tuple[int, int],
                      extraction_mode: str = "component_sums") -> List[int]:
        """
        MODIFIED DECRYPT FUNCTION - Returns vectors instead of scalars
        
        Mathematical Equation:
        Instead of: MCFE(x₁, x₂, ..., xₙ; y₁, y₂, ..., yₙ) = Σᵢ ⟨xᵢ, yᵢ⟩ (scalar)
        
        We compute: MCFE_vector(x₁, x₂, ..., xₙ) = [Σᵢ xᵢ₁, Σᵢ xᵢ₂, ..., Σᵢ xᵢₘ] (vector)
        
        Where each component j is extracted using basis vectors:
        component_j = MCFE(x₁, x₂, ..., xₙ; e₁ⱼ, e₂ⱼ, ..., eₙⱼ) = Σᵢ xᵢⱼ
        
        :param c: FeDDHMultiClient cipher text
        :param tag: Tag for decryption
        :param key: FeDDHMultiClient master key (with private key)
        :param bound: Bound for discrete log problem
        :param extraction_mode: "component_sums" or "weighted_average"
        :return: Vector of extracted components [c₁, c₂, ..., cₘ]
        """
        
        if not key.has_private_key():
            raise Exception("The master key must have private key for vector decryption")
        
        result_vector = []
        
        # Extract each vector component separately
        for j in range(key.m):  # For each dimension j = 1, 2, ..., m
            
            if extraction_mode == "component_sums":
                # Create basis vector extraction pattern for component j
                # y[i][j] = 1 for all clients i, others = 0
                y_basis = [[0] * key.m for _ in range(key.n)]
                for i in range(key.n):
                    y_basis[i][j] = 1  # Extract j-th component from all clients
                
                # Compute decryption key for this component
                d_j = FeDDHMultiClient._compute_decryption_key(y_basis, key)
                
            elif extraction_mode == "weighted_average":
                # Use integer weights (1 for each client) and divide result later
                y_weighted = [[0] * key.m for _ in range(key.n)]
                for i in range(key.n):
                    y_weighted[i][j] = 1  # Use weight of 1, divide final result by n
                
                # Compute decryption key for weighted average
                d_j = FeDDHMultiClient._compute_decryption_key(y_weighted, key)
            
            # Perform decryption for component j
            u1, u2 = key.hash(tag)
            u1, u2 = key.g * u1, key.g * u2
            
            cul = key.F.identity()
            
            # Compute inner product for component j
            for i in range(key.n):
                if extraction_mode == "component_sums":
                    # Only consider j-th component of each client
                    component_contribution = c[i].c[j] * y_basis[i][j]  # This is c[i][j] * 1
                    cul = cul + component_contribution
                elif extraction_mode == "weighted_average":
                    # Sum contribution of j-th component (divide by n later)
                    component_contribution = c[i].c[j] * y_weighted[i][j]  # This is c[i][j] * 1
                    cul = cul + component_contribution
            
            # Remove hash contribution
            cul = cul - (d_j[0] * u1 + d_j[1] * u2)
            
            # Extract component value
            component_value = discrete_log_bound(cul, key.g, bound)
            
            # For weighted average, divide by n to get the average
            if extraction_mode == "weighted_average":
                component_value = component_value // key.n  # Integer division for average
            
            result_vector.append(component_value)
        
        return result_vector

    @staticmethod
    def _compute_decryption_key(y_pattern: List[List[int]], key: _FeDDHMultiClient_MK) -> Tuple[int, int]:
        """
        Helper function to compute decryption key for given y pattern
        """
        cul_1 = 0
        cul_2 = 0
        
        for i in range(key.n):
            for j in range(key.m):
                s1, s2 = key.msk[i][j]
                cul_1 += s1 * y_pattern[i][j]
                cul_2 += s2 * y_pattern[i][j]
                cul_1 %= key.F.order()
                cul_2 %= key.F.order()
        
        return (cul_1, cul_2)

    @staticmethod
    def decrypt(c: List[_FeDDHMultiClient_C], tag: bytes,
                key: _FeDDHMultiClient_MK, sk: _FeDDHMultiClient_SK,
                bound: Tuple[int, int]) -> int:
        """
        ORIGINAL DECRYPT FUNCTION - Returns scalar (kept for backward compatibility)
        """
        u1, u2 = key.hash(tag)
        u1, u2 = key.g * u1, key.g * u2

        cul = key.F.identity()

        for i in range(key.n):
            cul = cul + inner_product(c[i].c, sk.y[i], key.F.identity())

        cul = cul - (sk.d[0] * u1 + sk.d[1] * u2)
        return discrete_log_bound(cul, key.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], key: _FeDDHMultiClient_MK) -> _FeDDHMultiClient_SK:
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
    def decrypt_dual(c: List[_FeDDHMultiClient_C], tag: bytes,
                    key: _FeDDHMultiClient_MK,
                    sk1: _FeDDHMultiClient_SK,
                    sk2: _FeDDHMultiClient_SK,
                    bound: Tuple[int, int]) -> Tuple[int, int]:
        """
        Decrypts two inner products simultaneously:
        - sk1 for function f1 = ⟨x, y⟩
        - sk2 for function f2 = ⟨x, x⟩ (self-inner product)
        """
        u1, u2 = key.hash(tag)
        u1, u2 = key.g * u1, key.g * u2

        cul1 = key.F.identity()
        cul2 = key.F.identity()

        for i in range(key.n):
            cul1 = cul1 + inner_product(c[i].c, sk1.y[i], key.F.identity())
            cul2 = cul2 + inner_product(c[i].c, sk2.y[i], key.F.identity())

        cul1 = cul1 - (sk1.d[0] * u1 + sk1.d[1] * u2)
        cul2 = cul2 - (sk2.d[0] * u1 + sk2.d[1] * u2)

        result1 = discrete_log_bound(cul1, key.g, bound)
        result2 = discrete_log_bound(cul2, key.g, bound)
        return result1, result2

    
    
    @staticmethod
    def keygen_y1_y2(y: List[List[int]], key: _FeDDHMultiClient_MK) -> _FeDDHMultiClient_SK:
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


    
    
    
# USAGE EXAMPLE WITH FIXED CALLS
if __name__ == "__main__":
    # Your exact setup
    n = 3
    m = 5
    x = [[i+1 for j in range(m)] for i in range(n)]
    y = [[j*10 for j in range(m)] for i in range(n)]
    y2 = [[j*5 for j in range(m)] for i in range(n)]
    
    print('x =', x)
    print('y =', y)
    
    tag = b"testingtag123"
    key = FeDDHMultiClient.generate(n, m)
    print('Generated key for', n, 'clients with vector dimension', m)
    
    # Encrypt each client's vector
    cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]
    print('Encrypted', len(cs), 'ciphertexts')
    
    # NEW: Use modified decrypt function to get vectors
    print("\n=== VECTOR EXTRACTION ===")
    
    # FIXED: Pass master key (key) instead of public key (key.get_public_key())
    component_sums = FeDDHMultiClient.decrypt_vector(cs, tag, key, (0, 9999), "component_sums")
    print('Component sums (Σᵢ xᵢⱼ):', component_sums)
    
    # Verify manually
    manual_sums = []
    for j in range(m):
        manual_sum = sum(x[i][j] for i in range(n))
        manual_sums.append(manual_sum)
    print('Manual verification:', manual_sums)
    print('Match:', component_sums == manual_sums)
    
    # FIXED: Pass master key instead of public key
    weighted_averages = FeDDHMultiClient.decrypt_vector(cs, tag, key, (0, 9999), "weighted_average")
    print('\nWeighted averages (1/n × Σᵢ xᵢⱼ):', weighted_averages)
    
    # Verify manually
    manual_avgs = []
    for j in range(m):
        manual_avg = sum(x[i][j] for i in range(n)) // n  # Use integer division to match
        manual_avgs.append(manual_avg)
    print('Manual verification:', manual_avgs)
    
    print("\n=== COMPARISON WITH ORIGINAL ===")
    
    # Original approach - individual dot products
    results = []
    for i in range(n):
        y_individual = [[0]*m for _ in range(n)]
        y_individual[i] = y[i]
        
        dk_fi = FeDDHMultiClient.keygen(y_individual, key)
        result_i = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), dk_fi, (0, 9999))
        results.append(result_i)
    
    print('Original dot products:', results)
    
    # Mathematical verification
    manual_dots = []
    for i in range(n):
        dot_product = sum(x[i][j] * y[i][j] for j in range(m))
        manual_dots.append(dot_product)
    print('Manual dot products:', manual_dots)
    print('Match:', results == manual_dots)
    
    
    print("\n=== Dual Decryption Example ===")

    # Decryption key for function vector y
    sk_y = FeDDHMultiClient.keygen(y, key)
    # Decryption key for function vector x (self-inner product)
    sk_x = FeDDHMultiClient.keygen(x, key)

    # Use the dual decryption method
    result_yx, result_xx = FeDDHMultiClient.decrypt_dual(cs, tag, key.get_public_key(), sk_y, sk_x, (0, 9999))

    print("Inner product ⟨x, y⟩ =", result_yx)
    print("Self inner product ⟨x, x⟩ =", result_xx)
    
    
    print("---------keygen_y1_y2---------")
    
    # Decryption key for function vector y
    sk_y1 = FeDDHMultiClient.keygen(y, key)
    sk_y2 = FeDDHMultiClient.keygen_y1_y2(y2, key)
    
    result_y1 = FeDDHMultiClient.decrypt_vector(cs, tag, key.get_public_key(), sk_y1, (0, 9999))
    result_y2 = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk_y2, (0, 9999))
    print("Inner product ⟨x, y⟩ =", result_y1)
    print("y2 inner product  =", result_y2)

    print("y2:",y2)