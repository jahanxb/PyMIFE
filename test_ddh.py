from mife.single.selective.ddh import FeDDH

n = 3
m = 5
x = [[i+1  for j in range(m)] for i in range(n)]
y = [[j* 10 for j in range(m)] for i in range(n)]

# Compute each dot product separately
results = []
for i in range(n):
    key_i = FeDDH.generate(m)
    c_i = FeDDH.encrypt(x[i], key_i)
    sk_i = FeDDH.keygen(y[i], key_i)
    result_i = FeDDH.decrypt(c_i, key_i.get_public_key(), sk_i, (0, 1000))
    results.append(result_i)

print('result:',results)