# from mife.multiclient.rom.ddh import FeDDHMultiClient


# if __name__ == '__main__':
#     n = 3
#     m = 5
#     #x = [[i+1  for j in range(m)] for i in range(n)]
#     #y = [[j* 10 for j in range(m)] for i in range(n)]
    
#     x = [[i + j for j in range(m)] for i in range(n)]
#     y = [[i - j + 10 for j in range(m)] for i in range(n)]
    
#     print('x=',x)
#     print('y=',y)
#     tag = b"testingtag123"
#     key = FeDDHMultiClient.generate(n, m)
#     cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]
    
#     print('Ciphertext: ',cs)
    
#     sk = FeDDHMultiClient.keygen(y, key)
#     print('sk=',sk)
#     m = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk, (0, 2000))
#     print('x=',x, '\n', 'y=',y , '\n' ,'m=',m,'\n','n=',n)


from mife.multiclient.rom.ddh import FeDDHMultiClient

n = 3
m = 5
x = [[i+1  for j in range(m)] for i in range(n)] # Is the input for the function we'll implement the functional encryption for
y = [[j* 10 for j in range(m)] for i in range(n)] # The label means the output of the function

print('x=',x)
print('y=',y)

y_individual = y

tag = b"testingtag123"

key = FeDDHMultiClient.generate(n, m) # this is sk_i, each sk_i has m keys
print('sk_i=',key) 
cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)] # key.get_enc_key takes s_i (the master  secret) and generate the encryption key which is the vector of s_i
print('Ciphertext:',cs)

results = []
for i in range(n):
    y_individual = [[0]*m for _ in range(n)]
    y_individual[i] = y[i]
    
    dk_fi = FeDDHMultiClient.keygen(y_individual, key) # Keygen takes the label (the ouput of function with the input x) and the master secret s_i
    
    result_i = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), dk_fi, (0, 9999))
    results.append(result_i)

print('Dot product:',results)



# from mife.multiclient.rom.ddh import FeDDHMultiClient

# def mcfe_individual_dot_products(x, y, tag=b"default", bounds=(0, 9999)):
#     n, m = len(x), len(x[0])
    
#     # Setup and encryption
#     key = FeDDHMultiClient.generate(n, m)
#     cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]
    
#     # Get individual dot products
#     results = []
#     for i in range(n):
#         y_individual = [[0]*m for _ in range(n)]
#         y_individual[i] = y[i]
#         sk_i = FeDDHMultiClient.keygen(y_individual, key)
#         result_i = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk_i, bounds)
#         results.append(result_i)
    
#     return results

# # Usage
# n, m = 3, 5
# x = [[i+1 for j in range(m)] for i in range(n)]
# y = [[j*10 for j in range(m)] for i in range(n)]

# results = mcfe_individual_dot_products(x, y)
# print(f"Individual dot products: {results}")