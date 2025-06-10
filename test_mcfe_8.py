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
        Generate a FeDDHMultiClient master key

        :param n: Number of clients
        :param m: Dimension of message vector for each client
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :param hash: Hash function to use. If set to None, a default hash function will be used
        :return: FeDDHMultiClient master key
        """
        if F is None:
            F = Zmod(getStrongPrime(1024))
        if hash is None:
            hash = _FeDDHMultiClient_Hash_Default(F.order().bit_length())

        g = F.generator()
        s = [[(randbelow(F.order()), randbelow(F.order())) for _ in range(m)] for _ in range(n)]

        return _FeDDHMultiClient_MK(g, n, m, F, hash, msk=s)

    @staticmethod
    def encrypt(x: List[int], tag: bytes, key: _FeDDHMultiClient_EncK) -> _FeDDHMultiClient_C:
        """
        Encrypt message vector

        :param x: Message vector
        :param tag: Tag for the encryption, usually time stamp
        :param key: Client encryption key
        :return: FeDDHMultiClient cipher text
        """
        if len(x) != len(key.enc_key):
            raise Exception(f"Encrypt vector must be of length {len(key.enc_key)}")

        u1, u2 = key.hash(tag)

        c = []

        for i in range(len(x)):
            s1, s2 = key.enc_key[i] 
            c.append((u1 * s1 + u2 * s2 + x[i]) * key.g) # generating element in the group, using generator

        return _FeDDHMultiClient_C(tag, c)

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
        :param key: FeDDHMultiClient master key # it means s_i
        :return: FeDDHMultiClient decryption key
        """
        if len(y) != key.n:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        cul_1 = 0
        cul_2 = 0
        # we have sk_i =(s_i, T_i), This function "keygen" takes s_i and y[i] and generates T_i matrix as follows 
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
    
    # # FIXED: Pass master key (key) instead of public key (key.get_public_key())
    # component_sums = FeDDHMultiClient.decrypt_vector(cs, tag, key, (0, 9999), "component_sums")
    # print('Component sums (Σᵢ xᵢⱼ):', component_sums)
    
    # # Verify manually
    # manual_sums = []
    # for j in range(m):
    #     manual_sum = sum(x[i][j] for i in range(n))
    #     manual_sums.append(manual_sum)
    # print('Manual verification:', manual_sums)
    # print('Match:', component_sums == manual_sums)
    
    # # FIXED: Pass master key instead of public key
    # weighted_averages = FeDDHMultiClient.decrypt_vector(cs, tag, key, (0, 9999), "weighted_average")
    # print('\nWeighted averages (1/n × Σᵢ xᵢⱼ):', weighted_averages)
    
    # # Verify manually
    # manual_avgs = []
    # for j in range(m):
    #     manual_avg = sum(x[i][j] for i in range(n)) // n  # Use integer division to match
    #     manual_avgs.append(manual_avg)
    # print('Manual verification:', manual_avgs)
    
    # print("\n=== COMPARISON WITH ORIGINAL ===")
    
    # # Original approach - individual dot products
    # results = []
    # for i in range(n):
    #     y_individual = [[0]*m for _ in range(n)]
    #     y_individual[i] = y[i]
        
    #     dk_fi = FeDDHMultiClient.keygen(y_individual, key)
    #     result_i = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), dk_fi, (0, 9999))
    #     results.append(result_i)
    
    # print('Original dot products:', results)
    
    # # Mathematical verification
    # manual_dots = []
    # for i in range(n):
    #     dot_product = sum(x[i][j] * y[i][j] for j in range(m))
    #     manual_dots.append(dot_product)
    # print('Manual dot products:', manual_dots)
    # print('Match:', results == manual_dots)
    
    
    # print("\n=== Dual Decryption Example ===")

    # # Decryption key for function vector y
    # sk_y = FeDDHMultiClient.keygen(y, key)
    # # Decryption key for function vector x (self-inner product)
    # sk_x = FeDDHMultiClient.keygen(x, key)

    # # Use the dual decryption method
    # result_yx, result_xx = FeDDHMultiClient.decrypt_dual(cs, tag, key.get_public_key(), sk_y, sk_x, (0, 9999))

    # print("Inner product ⟨x, y⟩ =", result_yx)
    # print("Self inner product ⟨x, x⟩ =", result_xx)
    
    
    # print("---------keygen_y1_y2---------")
    
    # # Decryption key for function vector y
    # sk_y1 = FeDDHMultiClient.keygen(y, key)
    # sk_y2 = FeDDHMultiClient.keygen_y1_y2(y2, key)
    
    # result_y1 = FeDDHMultiClient.decrypt_vector(cs, tag, key.get_public_key(), sk_y1, (0, 9999))
    # result_y2 = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk_y2, (0, 9999))
    # print("Inner product ⟨x, y⟩ =", result_y1)
    # print("y2 inner product  =", result_y2)

    # print("y2:",y2)