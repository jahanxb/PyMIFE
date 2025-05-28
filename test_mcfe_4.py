"""
MCFE Equations Validation - Comparing Mathematical Formulation with PyMIFE Implementation
Based on "Decentralized Multi-Client Functional Encryption for Inner Product" paper
"""

from mife.multiclient.rom.ddh import FeDDHMultiClient
import numpy as np

def validate_mcfe_equations():
    """
    Validate MCFE equations from Section 4 of the paper against PyMIFE implementation
    """
    print("=== MCFE Equations Validation ===")
    print("Based on Section 4: 'A Fully-Secure MCFE for Inner Product'\n")
    
    # Test parameters
    n = 3  # number of clients
    m = 5  # vector dimension
    
    # Test data - same as your example
    x = [[i+1 for j in range(m)] for i in range(n)]
    y = [[j*10 for j in range(m)] for i in range(n)]
    
    print(f"Input vectors:")
    print(f"x = {x}")
    print(f"y = {y}")
    print()
    
    # Paper Equation Implementation
    print("=== PAPER EQUATIONS ===")
    
    # Equation 1: Standard MCFE Sum
    print("1. Standard MCFE Equation:")
    print("   MCFE(x₁, x₂, ..., xₙ; y₁, y₂, ..., yₙ) = Σᵢ₌₁ⁿ ⟨xᵢ, yᵢ⟩")
    
    manual_individual = []
    for i in range(n):
        dot_product = sum(x[i][j] * y[i][j] for j in range(m))
        manual_individual.append(dot_product)
        print(f"   ⟨x{i+1}, y{i+1}⟩ = {dot_product}")
    
    manual_sum = sum(manual_individual)
    print(f"   Total sum = {manual_sum}")
    print()
    
    # Equation 2: Selector Pattern  
    print("2. Selector Pattern Equations:")
    print("   y_selector^(k) = [0⃗, 0⃗, ..., yₖ, ..., 0⃗]")
    print("   MCFE(x₁, x₂, ..., xₙ; y_selector^(k)) = ⟨xₖ, yₖ⟩")
    print()
    
    for k in range(n):
        print(f"   For k={k+1}:")
        y_selector = [[0]*m for _ in range(n)]
        y_selector[k] = y[k]
        print(f"     y_selector^({k+1}) = {y_selector}")
        
        # Manual calculation using selector pattern
        selector_result = 0
        for i in range(n):
            dot_prod = sum(x[i][j] * y_selector[i][j] for j in range(m))
            if dot_prod != 0:
                print(f"     ⟨x{i+1}, y_selector^({k+1})[{i+1}]⟩ = {dot_prod}")
            selector_result += dot_prod
        print(f"     Result = {selector_result}")
        print()
    
    # PyMIFE Implementation
    print("=== PyMIFE IMPLEMENTATION ===")
    
    tag = b"validation"
    key = FeDDHMultiClient.generate(n, m)
    cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]
    
    # Test 1: Standard MCFE (sum of all)
    sk_standard = FeDDHMultiClient.keygen(y, key)
    pymife_sum = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk_standard, (0, 9999))
    
    print(f"1. Standard MCFE Result: {pymife_sum}")
    
    # Test 2: Selector pattern for individual results
    pymife_individual = []
    for i in range(n):
        y_individual = [[0]*m for _ in range(n)]
        y_individual[i] = y[i]
        
        sk_i = FeDDHMultiClient.keygen(y_individual, key)
        result_i = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk_i, (0, 9999))
        pymife_individual.append(result_i)
    
    print(f"2. Individual Results: {pymife_individual}")
    print()
    
    # Validation
    print("=== VALIDATION RESULTS ===")
    
    # Check standard sum
    sum_valid = (manual_sum == pymife_sum)
    print(f"Standard MCFE Sum:")
    print(f"  Manual calculation: {manual_sum}")
    print(f"  PyMIFE result:      {pymife_sum}")
    print(f"  ✅ VALID" if sum_valid else f"  ❌ INVALID")
    print()
    
    # Check individual results
    individual_valid = (manual_individual == pymife_individual)
    print(f"Individual Results:")
    print(f"  Manual calculation: {manual_individual}")
    print(f"  PyMIFE result:      {pymife_individual}")
    print(f"  ✅ VALID" if individual_valid else f"  ❌ INVALID")
    print()
    
    # Verify sum relationship
    sum_of_individual = sum(pymife_individual)
    sum_relationship_valid = (sum_of_individual == pymife_sum)
    print(f"Sum Relationship Check:")
    print(f"  Sum of individual results: {sum_of_individual}")
    print(f"  Direct MCFE sum:          {pymife_sum}")
    print(f"  ✅ VALID" if sum_relationship_valid else f"  ❌ INVALID")
    print()
    
    # Mathematical verification
    print("=== MATHEMATICAL VERIFICATION ===")
    print("Verifying the core decryption equation:")
    print("[α] = Σᵢ [cᵢ] · yᵢ - [ũₗᵀ] · d̃")
    print("Where d̃ = Σᵢ s̃ᵢ · yᵢ")
    print()
    print("This expands to:")
    print("[α] = Σᵢ ([ũₗᵀs̃ᵢ + xᵢ] · yᵢ) - [ũₗᵀ] · (Σᵢ s̃ᵢ · yᵢ)")
    print("    = Σᵢ [ũₗᵀ] · s̃ᵢyᵢ + Σᵢ [xᵢ] · yᵢ - [ũₗᵀ] · Σᵢ yᵢs̃ᵢ")
    print("    = [Σᵢ xᵢyᵢ]")
    print()
    
    # Overall validation
    overall_valid = sum_valid and individual_valid and sum_relationship_valid
    print("=== FINAL RESULT ===")
    print(f"All equations validated: {'✅ SUCCESS' if overall_valid else '❌ FAILED'}")
    
    if overall_valid:
        print("\n🎉 The mathematical equations from the paper perfectly match")
        print("   the PyMIFE implementation results!")
        print("\n📝 Key validated equations:")
        print("   • Standard MCFE: Σᵢ ⟨xᵢ, yᵢ⟩")
        print("   • Selector pattern: y_selector^(k) = [0⃗, ..., yₖ, ..., 0⃗]")
        print("   • Individual extraction: MCFE(x; y_selector^(k)) = ⟨xₖ, yₖ⟩")
        print("   • Sum relationship: Σₖ individual_result[k] = total_sum")
    
    return overall_valid

def demonstrate_federated_learning_equations():
    """
    Demonstrate MCFE equations in federated learning context
    """
    print("\n" + "="*60)
    print("FEDERATED LEARNING APPLICATION")
    print("="*60)
    
    # Federated learning scenario
    n_clients = 3
    feature_dim = 4
    
    # Each client has local gradients/features
    client_gradients = [
        [0.1, 0.2, 0.3, 0.4],  # Client 1 gradients
        [0.2, 0.3, 0.4, 0.5],  # Client 2 gradients
        [0.3, 0.4, 0.5, 0.6]   # Client 3 gradients
    ]
    
    # Global model weights (same for all clients in aggregation)
    global_weights = [1.0, 2.0, 3.0, 4.0]
    
    print("Federated Learning Setup:")
    print(f"Client gradients: {client_gradients}")
    print(f"Global weights:   {global_weights}")
    print()
    
    # Mathematical formulation
    print("MCFE for Federated Learning:")
    print("Each client computes: ⟨local_gradient_i, global_weights⟩")
    print("Aggregator gets: Σᵢ ⟨gradient_i, weights⟩")
    print()
    
    # Manual calculation
    individual_contributions = []
    for i, grad in enumerate(client_gradients):
        contribution = sum(grad[j] * global_weights[j] for j in range(feature_dim))
        individual_contributions.append(contribution)
        print(f"Client {i+1} contribution: {contribution:.3f}")
    
    total_aggregation = sum(individual_contributions)
    print(f"Total aggregated value: {total_aggregation:.3f}")
    print()
    
    # Using MCFE
    y_weights = [global_weights for _ in range(n_clients)]  # Replicated for each client
    
    tag = b"federated_round_1"
    key = FeDDHMultiClient.generate(n_clients, feature_dim)
    cs = [FeDDHMultiClient.encrypt(client_gradients[i], tag, key.get_enc_key(i)) 
          for i in range(n_clients)]
    
    # Secure aggregation
    sk = FeDDHMultiClient.keygen(y_weights, key)
    mcfe_result = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk, (0, 100))
    
    print(f"MCFE Secure Aggregation Result: {mcfe_result}")
    print(f"Manual Calculation Result:      {total_aggregation:.0f}")
    print(f"Match: {'✅' if abs(mcfe_result - total_aggregation) < 0.001 else '❌'}")

if __name__ == "__main__":
    # Run main validation
    success = validate_mcfe_equations()
    
    # Run federated learning demo
    demonstrate_federated_learning_equations()