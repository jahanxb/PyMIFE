from mife.multiclient.rom.ddh import FeDDHMultiClient
import numpy as np

def validate_mcfe_equations():
    """
    Validate MCFE selector pattern equations by comparing:
    1. PyMIFE implementation results
    2. Manual mathematical computation
    """
    
    # Test data
    n = 3  # clients
    m = 5  # vector dimension
    
    x = [[i+1 for j in range(m)] for i in range(n)]
    y = [[j*10 for j in range(m)] for i in range(n)]
    
    print("=== MCFE Mathematical Validation ===")
    print(f"x = {x}")
    print(f"y = {y}")
    print()
    
    # Method 1: PyMIFE Selector Pattern Implementation
    tag = b"validation_test"
    key = FeDDHMultiClient.generate(n, m)
    cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]
    
    pymife_results = []
    for i in range(n):
        # Selector pattern: y_selector^(i) = [0, 0, ..., y_i, ..., 0]
        y_selector = [[0]*m for _ in range(n)]
        y_selector[i] = y[i]
        
        sk_i = FeDDHMultiClient.keygen(y_selector, key)
        result_i = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk_i, (0, 9999))
        pymife_results.append(result_i)
    
    print("Method 1 - PyMIFE Selector Pattern:")
    print(f"Results: {pymife_results}")
    print()
    
    # Method 2: Manual Mathematical Computation
    manual_results = []
    for i in range(n):
        # Compute ⟨x_i, y_i⟩ = Σⱼ x_i[j] * y_i[j]
        dot_product = sum(x[i][j] * y[i][j] for j in range(m))
        manual_results.append(dot_product)
    
    print("Method 2 - Manual Mathematical Computation:")
    print("Individual dot products ⟨xᵢ, yᵢ⟩:")
    for i in range(n):
        terms = [f"{x[i][j]}×{y[i][j]}" for j in range(m)]
        computation = " + ".join(terms)
        print(f"  Client {i+1}: [{', '.join(map(str, x[i]))}] · [{', '.join(map(str, y[i]))}]")
        print(f"           = {computation} = {manual_results[i]}")
    
    print(f"\nManual Results: {manual_results}")
    print()
    
    # Method 3: Equation Validation
    print("Method 3 - Equation Validation:")
    print("MCFE Selector Equation: MCFE(x₁,...,xₙ; y_selector^(k)) = ⟨xₖ, yₖ⟩")
    print("\nStep-by-step verification:")
    
    for k in range(n):
        print(f"\nFor client {k+1} (k={k}):")
        print(f"  y_selector^({k}) = {[[0]*m if i != k else y[i] for i in range(n)]}")
        
        # Show the summation breakdown
        sum_terms = []
        for i in range(n):
            if i == k:
                term_value = sum(x[i][j] * y[i][j] for j in range(m))
                sum_terms.append(f"⟨x_{i+1}, y_{i+1}⟩ = {term_value}")
            else:
                sum_terms.append(f"⟨x_{i+1}, 0⟩ = 0")
        
        print(f"  Σᵢ ⟨xᵢ, y_selector^({k})[i]⟩ = {' + '.join(sum_terms)}")
        print(f"  = {manual_results[k]}")
    
    # Validation check
    print("\n=== VALIDATION RESULTS ===")
    validation_passed = pymife_results == manual_results
    print(f"PyMIFE Results: {pymife_results}")
    print(f"Manual Results: {manual_results}")
    print(f"Validation: {'✅ PASSED' if validation_passed else '❌ FAILED'}")
    
    if not validation_passed:
        print("Differences found:")
        for i in range(n):
            if pymife_results[i] != manual_results[i]:
                print(f"  Client {i+1}: PyMIFE={pymife_results[i]}, Manual={manual_results[i]}")
    
    # Test standard MCFE sum
    print("\n=== STANDARD MCFE (Sum of all) ===")
    y_standard = y  # All clients active
    sk_sum = FeDDHMultiClient.keygen(y_standard, key)
    mcfe_sum = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk_sum, (0, 9999))
    manual_sum = sum(manual_results)
    
    print(f"MCFE Sum: {mcfe_sum}")
    print(f"Manual Sum: {manual_sum}")
    print(f"Sum Validation: {'✅ PASSED' if mcfe_sum == manual_sum else '❌ FAILED'}")
    
    return pymife_results, manual_results, validation_passed

# Run validation
if __name__ == "__main__":
    validate_mcfe_equations()