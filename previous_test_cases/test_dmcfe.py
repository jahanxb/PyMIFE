# from mife.multiclient.decentralized.ddh import FeDDHMultiClientDec


# if __name__ == '__main__':
#     n = 32
#     m = 52
#     x = [[i + j for j in range(m)] for i in range(n)]
#     y = [[i - j + 10 for j in range(m)] for i in range(n)]
#     tag = b"testingtag123"
#     pub = FeDDHMultiClientDec.generate(n, m)
#     keys = [pub.generate_party(i) for i in range(n)]

#     for i in range(n):
#         for j in range(n):
#             if i == j: continue
#             keys[i].exchange(j, keys[j].get_exc_public_key())

#     for i in range(n):
#         keys[i].generate_share()

#     cs = [FeDDHMultiClientDec.encrypt(x[i], tag, keys[i]) for i in range(n)]
#     sk = [FeDDHMultiClientDec.keygen(y, keys[i]) for i in range(n)]
#     m = FeDDHMultiClientDec.decrypt(cs, tag, pub, sk, (0, 2000))


# '''
# from mife.multiclient.rom.ddh import FeDDHMultiClient
# import json

# n = 32767
# m = 52767
# x = [[i + j for j in range(m)] for i in range(n)]
# y = [[i - j + 10 for j in range(m)] for i in range(n)]
# tag = b"testingtag123"
# key = FeDDHMultiClient.generate(n, m)
# cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]
# sk = FeDDHMultiClient.keygen(y, key)
# print(f"enc_key = {json.dumps([key.get_enc_key(i).export() for i in range(n)])}")
# print(f"msk = {json.dumps(key.export())}")
# print(f"ct = {[json.dumps(cs[i].export()) for i in range(n)]}")
# print(f"secret_key = {json.dumps(sk.export())}")
# print(f"pub_key = {json.dumps(key.get_public_key().export())}")

# '''
# import numpy as np
# from mife.multiclient.rom.ddh import FeDDHMultiClient
# import json

# # Parameters
# n, m = 32, 52
# tag = b"testingtag123"

# # 1) Build x and y as NumPy arrays via broadcasting
# i = np.arange(n).reshape(n, 1)   # shape (n, 1)
# j = np.arange(m)                 # shape (m,)
# x = i + j                        # shape (n, m): each row i has values i + j
# y = i - j + 10                   # shape (n, m): each row i has values i - j + 10

# # 2) Generate the multi-client key
# key = FeDDHMultiClient.generate(n, m)

# # 3) Encrypt each row of x
# cs = []
# for idx, row in enumerate(x):
#     enc_key = key.get_enc_key(idx)
#     # The library may accept a NumPy array directly; if not, convert to list:
#     row_data = row.tolist()
#     cs.append(FeDDHMultiClient.encrypt(row_data, tag, enc_key))

# # 4) Generate the secret key on y
# # If keygen expects a list of lists, convert y to nested Python lists:
# sk = FeDDHMultiClient.keygen(y.tolist(), key)

# # 5) Serialize and print everything
# enc_keys_exported = [key.get_enc_key(i).export() for i in range(n)]
# print("enc_key =", json.dumps(enc_keys_exported))
# print("msk =", json.dumps(key.export()))
# print("ct =", json.dumps([ct.export() for ct in cs]))
# print("secret_key =", json.dumps(sk.export()))
# print("pub_key =", json.dumps(key.get_public_key().export()))


from mife.multiclient.decentralized.ddh import FeDDHMultiClientDec

n = 3
m = 5
# x = [[i + j for j in range(m)] for i in range(n)]
# y = [[i - j + 10 for j in range(m)] for i in range(n)]

x = [[i+1  for j in range(m)] for i in range(n)] # Is the input for the function we'll implement the functional encryption for
y = [[j* 10 for j in range(m)] for i in range(n)] # The label means the output of the function


tag = b"testingtag123"
pub = FeDDHMultiClientDec.generate(n, m)
keys = [pub.generate_party(i) for i in range(n)]

for i in range(n):
    for j in range(n):
        if i == j: continue
        keys[i].exchange(j, keys[j].get_exc_public_key())

for i in range(n):
    keys[i].generate_share()

cs = [FeDDHMultiClientDec.encrypt(x[i], tag, keys[i]) for i in range(n)]
sk = [FeDDHMultiClientDec.keygen(y, keys[i]) for i in range(n)]
m = FeDDHMultiClientDec.decrypt(cs, tag, pub, sk, (0, 2000))

print('x=',x, '\n', 'y=',y , '\n' ,'m=',m,'\n','n=',n)