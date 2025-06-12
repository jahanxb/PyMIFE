# File: tests/multiclient/decentralized/test_dmcfe_section5.py

import time
import logging
from typing import List, Tuple
from tests.test_base import TestBase

# Import our DMCFE implementation
from mife.multiclient.decentralized.dmcfe_section5 import (
    DMCFE_Section5, 
    _DMCFE_PublicParams, 
    _DMCFE_SenderKey,
    verify_t_matrix_constraint
)

class TestDMCFE_Section5(TestBase):
    """Test cases for Section 5 DMCFE implementation"""
    
    logging.getLogger().setLevel(logging.INFO)

    def test_setup_protocol(self):
        """Test the setup protocol creates valid keys and satisfies constraints"""
        n = 3
        mpk, sender_keys = DMCFE_Section5.setup(n, bits=512)  # Use smaller bits for testing
        
        # Verify we have the right number of keys
        self.assertEqual(len(sender_keys), n)
        
        # Verify each sender has correct index
        for i, key in enumerate(sender_keys):
            self.assertEqual(key.index, i)
            
        # Verify T matrix constraint: sum of all T_i = 0
        self.assertTrue(verify_t_matrix_constraint(sender_keys))
        
        # Verify public parameters
        self.assertEqual(mpk.n, n)
        self.assertIsNotNone(mpk.pairing)
        self.assertIsNotNone(mpk.H1)
        self.assertIsNotNone(mpk.H2)
        
        logging.info(f"Setup protocol test passed for n={n}")

    def test_basic_encryption_decryption(self):
        """Test basic encryption and decryption functionality"""
        start = time.time()
        
        n = 3
        x = [5, 10, 15]  # Messages from each sender
        y = [1, 2, 3]    # Function vector
        label = b"test_label_001"
        
        # Setup
        mpk, sender_keys = DMCFE_Section5.setup(n, bits=512)
        
        # Encrypt messages
        ciphertexts = []
        for i in range(n):
            ct = DMCFE_Section5.encrypt(x[i], label, sender_keys[i], mpk)
            ciphertexts.append(ct)
            
        # Generate partial decryption keys
        label_f = "function_inner_product"
        partial_keys = []
        for i in range(n):
            pk = DMCFE_Section5.dkey_gen_share(y, label_f, sender_keys[i], mpk)
            partial_keys.append(pk)
            
        # Combine partial keys - FIXED: removed extra mpk parameter
        dk_f = DMCFE_Section5.dkey_combine(partial_keys, y, label_f)
        
        # Decrypt
        result = DMCFE_Section5.decrypt(ciphertexts, label, dk_f, mpk, (-1000, 1000))
        
        # Verify result
        expected = sum(x[i] * y[i] for i in range(n))  # Inner product: 5*1 + 10*2 + 15*3 = 70
        self.assertEqual(result, expected)
        
        end = time.time()
        logging.info(f"Basic DMCFE test passed (n={n}): {end - start:.4f}s, result={result}")

    def test_larger_vectors(self):
        """Test with larger number of senders and different values"""
        start = time.time()
        
        n = 5
        x = [i * 10 + 5 for i in range(n)]  # [5, 15, 25, 35, 45]
        y = [i + 1 for i in range(n)]       # [1, 2, 3, 4, 5]
        label = b"larger_test_vector"
        
        # Setup
        mpk, sender_keys = DMCFE_Section5.setup(n, bits=512)
        
        # Encrypt
        ciphertexts = []
        for i in range(n):
            ct = DMCFE_Section5.encrypt(x[i], label, sender_keys[i], mpk)
            ciphertexts.append(ct)
            
        # Generate and combine keys
        label_f = "large_vector_function"
        partial_keys = []
        for i in range(n):
            pk = DMCFE_Section5.dkey_gen_share(y, label_f, sender_keys[i], mpk)
            partial_keys.append(pk)
            
        # FIXED: removed extra mpk parameter
        dk_f = DMCFE_Section5.dkey_combine(partial_keys, y, label_f)
        
        # Decrypt
        result = DMCFE_Section5.decrypt(ciphertexts, label, dk_f, mpk, (-10000, 10000))
        
        # Verify: 5*1 + 15*2 + 25*3 + 35*4 + 45*5 = 5 + 30 + 75 + 140 + 225 = 475
        expected = sum(x[i] * y[i] for i in range(n))
        self.assertEqual(result, expected)
        
        end = time.time()
        logging.info(f"Large vector DMCFE test passed (n={n}): {end - start:.4f}s, result={result}")

    def test_negative_values(self):
        """Test with negative values in vectors"""
        start = time.time()
        
        n = 4
        x = [10, -5, 8, -12]    # Mix of positive and negative
        y = [2, -1, 3, 1]       # Mix of positive and negative
        label = b"negative_values_test"
        
        # Setup
        mpk, sender_keys = DMCFE_Section5.setup(n, bits=512)
        
        # Encrypt
        ciphertexts = []
        for i in range(n):
            ct = DMCFE_Section5.encrypt(x[i], label, sender_keys[i], mpk)
            ciphertexts.append(ct)
            
        # Generate and combine keys
        label_f = "negative_function"
        partial_keys = []
        for i in range(n):
            pk = DMCFE_Section5.dkey_gen_share(y, label_f, sender_keys[i], mpk)
            partial_keys.append(pk)
            
        # FIXED: removed extra mpk parameter
        dk_f = DMCFE_Section5.dkey_combine(partial_keys, y, label_f)
        
        # Decrypt
        result = DMCFE_Section5.decrypt(ciphertexts, label, dk_f, mpk, (-1000, 1000))
        
        # Verify: 10*2 + (-5)*(-1) + 8*3 + (-12)*1 = 20 + 5 + 24 - 12 = 37
        expected = sum(x[i] * y[i] for i in range(n))
        self.assertEqual(result, expected)
        
        end = time.time()
        logging.info(f"Negative values DMCFE test passed (n={n}): {end - start:.4f}s, result={result}")

    def test_t_matrix_constraint_verification(self):
        """Test that T matrix constraint verification works correctly"""
        n = 4
        mpk, sender_keys = DMCFE_Section5.setup(n, bits=512)
        
        # Should pass the constraint check
        self.assertTrue(verify_t_matrix_constraint(sender_keys))
        
        # Manually break the constraint and verify it fails
        sender_keys[0].T_i[0][0] = sender_keys[0].T_i[0][0] + sender_keys[0].T_i[0][0].group(1)
        self.assertFalse(verify_t_matrix_constraint(sender_keys))
        
        logging.info("T matrix constraint verification test passed")

    def test_export_functionality(self):
        """Test that all components can be exported"""
        n = 2
        mpk, sender_keys = DMCFE_Section5.setup(n, bits=512)
        
        # Test public params export
        mpk_export = mpk.export()
        self.assertIn("n", mpk_export)
        self.assertEqual(mpk_export["n"], n)
        
        # Test sender key export
        for key in sender_keys:
            key_export = key.export()
            self.assertIn("index", key_export)
            self.assertIn("s_tilde_i", key_export)
            self.assertIn("T_i", key_export)
            
        # Test ciphertext export
        ct = DMCFE_Section5.encrypt(42, b"test", sender_keys[0], mpk)
        ct_export = ct.export()
        self.assertIn("index", ct_export)
        self.assertIn("label", ct_export)
        
        # Test partial key export
        y = [1, 2]
        pk = DMCFE_Section5.dkey_gen_share(y, "test_func", sender_keys[0], mpk)
        pk_export = pk.export()
        self.assertIn("index", pk_export)
        self.assertIn("label_f", pk_export)
        
        logging.info("Export functionality test passed")

if __name__ == '__main__':
    import unittest
    unittest.main()