from mife.single.selective.ddh import FeDDH


if __name__ == '__main__':
    n = 10
    x = [i for i in range(n)]
    y = [i + 10 for i in range(n)]
    key = FeDDH.generate(n)
    c = FeDDH.encrypt(x, key)
    sk = FeDDH.keygen(y, key)
    m = FeDDH.decrypt(c, key.get_public_key(), sk, (0, 1000))