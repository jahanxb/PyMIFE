from mife.multiclient.decentralized.dmcfe_section5 import DMCFE_Section5

# Parameters
n = 3  # Number of senders
m = 5  # Vector dimension (each sender has m-dimensional input)

# Input data: each sender i has an m-dimensional vector x_i
x = [[i+1 for j in range(m)] for i in range(n)]  # x[i] is sender i's input vector
print('Input vectors x =', x)

# Function vectors: each y[i] defines a different inner product function
y = [[j * 10 for j in range(m)] for i in range(n)]  # y[i] is the i-th function vector
print('Function vectors y =', y)

# Label for encryption
tag = b"testingtag123"

print("\n=== DMCFE Protocol Execution ===")

# 1. SETUP: Interactive setup between n senders (decentralized)
print("\n1. Setup Protocol:")
mpk, sender_keys = DMCFE_Section5.setup(n, bits=512)
print(f"   Generated public parameters for {n} senders")
print(f"   Each sender has secret key with T-matrix constraint satisfied")

# 2. ENCRYPTION: Each sender encrypts their input
print("\n2. Encryption Phase:")
ciphertexts = []
for i in range(n):
    # For DMCFE, each sender encrypts a single value (inner product component)
    # We'll compute the inner product of sender i's vector with a test function
    # For simplicity, let's use the first function vector y[0]
    inner_prod_i = sum(x[i][j] * y[0][j] for j in range(m))  # x[i] · y[0]
    
    ct_i = DMCFE_Section5.encrypt(inner_prod_i, tag, sender_keys[i], mpk)
    ciphertexts.append(ct_i)
    print(f"   Sender {i}: encrypted {inner_prod_i} = x[{i}] · y[0]")

print(f"   Total ciphertexts: {len(ciphertexts)}")

# 3. FUNCTIONAL KEY GENERATION: Test different function vectors
print("\n3. Functional Key Generation & Decryption:")
results = []

for func_idx in range(n):  # Test each function vector
    print(f"\n   Function {func_idx}: y[{func_idx}] = {y[func_idx]}")
    
    # For DMCFE, the function vector defines the linear combination of encrypted values
    # We use a simple function vector [1, 1, 1] to sum all encrypted values
    dmcfe_function_vector = [1] * n  # Sum all senders' contributions
    
    # Each sender generates their partial decryption key
    partial_keys = []
    label_f = f"function_vector_{func_idx}"
    
    for i in range(n):
        pk_i = DMCFE_Section5.dkey_gen_share(
            dmcfe_function_vector, 
            label_f, 
            sender_keys[i], 
            mpk
        )
        partial_keys.append(pk_i)
    
    # Combine partial keys into functional decryption key
    dk_f = DMCFE_Section5.dkey_combine(partial_keys, dmcfe_function_vector, label_f)
    
    # Decrypt to get the result
    result = DMCFE_Section5.decrypt(ciphertexts, tag, dk_f, mpk, (-10000, 10000))
    results.append(result)
    
    print(f"   Result: {result}")

print(f"\n=== Results Summary ===")
print(f"Function results: {results}")

# Verify the results manually
print(f"\n=== Manual Verification ===")
expected_results = []
for func_idx in range(n):
    # Expected result: sum of (x[i] · y[0]) for all senders i
    # Since we encrypted inner_prod_i = x[i] · y[0] and used function [1,1,1]
    expected = sum(sum(x[i][j] * y[0][j] for j in range(m)) for i in range(n))
    expected_results.append(expected)
    print(f"Expected result for function {func_idx}: {expected}")

print(f"\nExpected results: {expected_results}")

# Additional test: Different encryption scenario
print(f"\n=== Alternative Test: Individual Component Encryption ===")

# Test encrypting individual components instead of full inner products
print("\nEncrypting individual vector components:")
for component_idx in range(min(m, 3)):  # Test first 3 components
    print(f"\nTesting component {component_idx}:")
    
    # Encrypt the component_idx-th element of each sender's vector
    component_ciphertexts = []
    for i in range(n):
        ct_i = DMCFE_Section5.encrypt(x[i][component_idx], tag, sender_keys[i], mpk)
        component_ciphertexts.append(ct_i)
        print(f"   Sender {i}: encrypted x[{i}][{component_idx}] = {x[i][component_idx]}")
    
    # Use function vector that corresponds to y[0][component_idx]
    test_function = [y[0][component_idx]] * n  # Weight each sender's component
    
    # Generate keys and decrypt
    partial_keys = []
    label_f = f"component_{component_idx}_test"
    
    for i in range(n):
        pk_i = DMCFE_Section5.dkey_gen_share(test_function, label_f, sender_keys[i], mpk)
        partial_keys.append(pk_i)
    
    dk_f = DMCFE_Section5.dkey_combine(partial_keys, test_function, label_f)
    result = DMCFE_Section5.decrypt(component_ciphertexts, tag, dk_f, mpk, (-10000, 10000))
    
    # Expected: sum of (x[i][component_idx] * y[0][component_idx]) for all i
    expected = sum(x[i][component_idx] * y[0][component_idx] for i in range(n))
    print(f"   DMCFE result: {result}")
    print(f"   Expected: {expected}")
    print(f"   Match: {result == expected}")

print(f"\n=== DMCFE Protocol Test Complete ===")