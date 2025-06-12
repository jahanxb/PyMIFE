from mife.multiclient.rom.ddh import FeDDHMultiClient


if __name__ == '__main__':
    n = 3
    m = 5
    x = [[i+1  for j in range(m)] for i in range(n)]
    y = [[j* 10 for j in range(m)] for i in range(n)]
    tag = b"testingtag123"
    key = FeDDHMultiClient.generate(n, m)
    cs = [FeDDHMultiClient.encrypt(x[i], tag, key.get_enc_key(i)) for i in range(n)]
    sk = FeDDHMultiClient.keygen(y, key)
    m = FeDDHMultiClient.decrypt(cs, tag, key.get_public_key(), sk, (0, 2000))
    print('x=',x, '\n', 'y=',y , '\n' ,'m=',m,'\n','n=',n)