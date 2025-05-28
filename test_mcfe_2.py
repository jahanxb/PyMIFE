# from mife.multiclient.rom.ddh import FeDDHMultiClient

# # Your example data
# x_data = [3, 4, 5]
# y_data = [10, 100, 1000]

# # Multi-client setup: each client has one element
# n = 3  # 3 clients
# m = 1  # each client has 1 value

# # Reshape for multi-client format
# x = [[x_data[i]] for i in range(n)]  # [[3], [4], [5]]
# y = [[y_data[i]] for i in range(n)]  # [[10], [100], [1000]]

# print(f"Client data: x = {x}")
# print(f"Function: y = {y}")

# tag = b"demo"
# key = FeDDHMultiClient.generate(n, m)

# # Each client encrypts independently
# cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]
# print(f"Encrypted by {n} different clients")

# # Generate function key and decrypt
# sk = FeDDHMultiClient.keygen(y, key)
# result = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk, (0, 10000))

# print(f"MCFE Result: {result}")
# print(f"Expected: {sum(x_data[i] * y_data[i] for i in range(n))}")


from mife.multiclient.rom.ddh import FeDDHMultiClient

# Federated Learning Scenario
n = 3  # 3 clients (hospitals, devices, etc.)
m = 5  # feature/gradient dimension

# Each client has their own feature vector/gradient
x1 = [1, 2, 3, 4, 5]    # Client 1's local gradient/features
x2 = [2, 3, 4, 5, 6]    # Client 2's local gradient/features  
x3 = [3, 4, 5, 6, 7]    # Client 3's local gradient/features

# Aggregator has ONE query vector (model weights/function)
y_aggregator = [10, 20, 30, 40, 50]  # Same for all clients

# Multi-client format
x = [x1, x2, x3]
y = [y_aggregator, y_aggregator, y_aggregator]  # Replicated for each client

print("=== Federated Learning with MCFE ===")
print(f"Client 1 data: {x1}")
print(f"Client 2 data: {x2}") 
print(f"Client 3 data: {x3}")
print(f"Aggregator query: {y_aggregator}")

tag = b"federated_round_1"
key = FeDDHMultiClient.generate(n, m)

# Each client encrypts their data independently (privacy preserved)
cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]

# Aggregator generates function key
sk = FeDDHMultiClient.keygen(y, key)

# Secure aggregation: sum of all client contributions
result = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk, (0, 5000))

print(f"\nMCFE Aggregated Result: {result}")

# Verify: sum of individual dot products
individual_results = [sum(x[i][j] * y[i][j] for j in range(m)) for i in range(n)]
expected_sum = sum(individual_results)
print(f"Expected (sum of dot products): {expected_sum}")
print(f"Individual contributions: {individual_results}")