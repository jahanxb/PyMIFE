from mife.multiclient.decentralized.palia import Palia

n = 3
m = 5
x = [[i + j for j in range(m)] for i in range(n)]
y = [[i - j + 10 for j in range(m)] for i in range(n)]

tag = b"testingtag123"
pub = Palia.generate(n, m)
keys = [pub.generate_party(i) for i in range(n)]
for i in range(n):
    for j in range(n):
        if i == j: continue
        keys[i].exchange(j, keys[j].get_exc_public_key())
        
for i in range(n):
    keys[i].generate_share()
    
mk = Palia.generate_query_key(pub)
pk = mk.getPublicKey()
enc_y = Palia.encrypt_query(y, pk, pub)

cs = [Palia.encrypt(x[i], tag, keys[i]) for i in range(n)]
sk = [Palia.keygen(enc_y, keys[i]) for i in range(n)]
m = Palia.decrypt(cs, tag, pub, sk, y, mk, (0, 2000))