from pypbc import *
import math
import random
import sys
import time

SECURITY = 100
PRIME_BITS = 256
VERSION_STRING = "0.3"
BLOCK_SIZE = 16
KEY_SIZE = 256

class Token:
    K = None
    K0 = None
    Ks = None

    def __init__(self, K, K0, Ks):
        self.K = K
        self.K0 = K0
        self.Ks = Ks

    def __str__(self):
        print("token tostr is invoked")
        s = ""
        s += str(self.K) + "\n"
        s += str(self.K0) + "\n"
        s += str(len(self.Ks)) + "\n"
        for k in self.Ks:
            s += str(k[0]) + "\n"
            s += str(k[1]) + "\n"
        return s

class Ciphertext:
    CPrime = None
    C = None
    C0 = None
    Cs = None

    def __init__(self, C, C0, Cs):
        self.C = C
        self.C0 = C0
        self.Cs = Cs

    def __str__(self):
        s = ""
        s += str(self.CPrime) + "\n"
        s += str(self.C) + "\n"
        s += str(self.C0) + "\n"
        s += str(len(self.Cs)) + "\n"
        for c in self.Cs:
            s += str(c[0]) + "\n"
            s += str(c[1]) + "\n"
        return s

    @classmethod
    def fromStr(cls, pairing, s):
        lines = s.splitlines()

        str_CPrime = lines.pop(0)
        CPrime = Element(pairing, GT)
        CPrime.input_value(str_CPrime)

        str_C = lines.pop(0)
        C = Element(pairing, G1)
        C.input_value(str_C)

        str_C0 = lines.pop(0)
        C0 = Element(pairing, G1)
        C0.input_value(str_C0)

        securityParam = int(lines.pop(0))
        Cs = []
        for i in range(securityParam):
            str_C_1 = lines.pop(0)
            C_1 = Element(pairing, G1)
            C_1.input_value(str_C_1)

            str_C_2 = lines.pop(0)
            C_2 = Element(pairing, G1)
            C_2.input_value(str_C_2)

            Cs.append((C_1, C_2))

        return cls(CPrime, C, C0, Cs)

class SecretKey:
    g_G_p = None
    g_G_q = None
    g_G_r = None
    g_G_s = None
    hs = None
    us = None
    h_gamma = None
    P = None

    def __init__(self, g_G_p, g_G_q, g_G_r, g_G_s, hs, us, h_gamma, P):
        self.g_G_p = g_G_p
        self.g_G_q = g_G_q
        self.g_G_r = g_G_r
        self.g_G_s = g_G_s
        self.hs = hs
        self.us = us
        self.h_gamma = h_gamma
        self.P = P

    def __str__(self):
        s = ""
        s += str(self.g_G_p) + "\n"
        s += str(self.g_G_q) + "\n"
        s += str(self.g_G_r) + "\n"
        s += str(self.g_G_s) + "\n"
        s += str(len(self.hs)) + "\n"

        for (h1, h2) in self.hs:
            s += str(h1) + "\n"
            s += str(h2) + "\n"
        for (u1, u2) in self.us:
            s += str(u1) + "\n"
            s += str(u2) + "\n"
        s += str(self.h_gamma) + "\n"
        s += str(self.P) + "\n"

        return s

    @classmethod
    def fromStr(cls, pairing, s):
        lines = s.splitlines()
        str_g_G_p = lines.pop(0)
        g_G_p = Element(pairing, G1)
        g_G_p.input_value(str_g_G_p)

        str_g_G_q = lines.pop(0)
        g_G_q = Element(pairing, G1)
        g_G_q.input_value(str_g_G_q)

        str_g_G_r = lines.pop(0)
        g_G_r = Element(pairing, G1)
        g_G_r.input_value(str_g_G_r)

        str_g_G_s = lines.pop(0)
        g_G_s = Element(pairing, G1)
        g_G_s.input_value(str_g_G_s)

        securityParam = int(lines.pop(0))

        hs = []
        us = []
        for i in range(securityParam):
            str_h_1 = lines.pop(0)
            h_1 = Element(pairing, G1)
            h_1.input_value(str_h_1)

            str_h_2 = lines.pop(0)
            h_2 = Element(pairing, G1)
            h_2.input_value(str_h_2)

            hs.append((h_1, h_2))

        for i in range(securityParam):
            str_u_1 = lines.pop(0)
            u_1 = Element(pairing, G1)
            u_1.input_value(str_u_1)

            str_u_2 = lines.pop(0)
            u_2 = Element(pairing, G1)
            u_2.input_value(str_u_2)

            us.append((u_1, u_2))

        str_h_gamma = lines.pop(0)
        h_gamma = Element(pairing, G1)
        h_gamma.input_value(str_h_gamma)

        str_P = lines.pop(0)
        P = Element(pairing, GT)
        P.input_value(str_P)

        return cls(g_G_p, g_G_q, g_G_r, g_G_s, hs, us, h_gamma, P)

class MyCryptosystem:
    def __init__(self, security, pairing, params, sk, g_GT, dlog, tags, \
        strength):
        if (strength is not None):
            self.prime_bits = strength
        else:
            self.prime_bits = PRIME_BITS
        self.security = security
        self.pairing = pairing
        self.params = params
        self.sk = sk
        self.g_GT = g_GT
        self.dlog = dlog
        self.tags = tags

    @classmethod
    def new(cls, securityParam, strength):
        if (strength is not None):
            prime_bits = strength
        else:
            prime_bits = PRIME_BITS

        # Select p, q, r, s
        p = get_random_prime(prime_bits)
        q = get_random_prime(prime_bits)
        r = get_random_prime(prime_bits)
        s = get_random_prime(prime_bits)

        # Make n
        n = p * q * r * s

        # Build the params
        params = Parameters(n=n)

        # Build the pairing
        pairing = Pairing(params)

        # temp = Element(pairing, G1)
        #
        # print("temp type: -------------------")
        # print(type(temp))

        # Find the generators for the G_p, G_q, G_r, and G_s subgroups
        g_G_p = Element.random(pairing, G1) ** (q * r * s)
        g_G_r = Element.random(pairing, G1) ** (p * q * s)
        g_G_q = Element.random(pairing, G1) ** (p * r * s)
        g_G_s = Element.random(pairing, G1) ** (p * r * q)

        # Choose the random h's and u's
        hs = []
        us = []
        for i in range(securityParam):
            hs.append((g_G_p ** Element.random(pairing, Zr), \
                       g_G_p ** Element.random(pairing, Zr)))
            us.append((g_G_p ** Element.random(pairing, Zr), \
                       g_G_p ** Element.random(pairing, Zr)))
            sys.stdout.write('.')
            sys.stdout.flush()
        sys.stdout.write('\n')

        # Choose gamma and create P, used for decryption
        gamma = Element(pairing, Zr, get_random(p))
        h = g_G_p ** Element.random(pairing, Zr)
        P = pairing.apply(g_G_p, h) ** gamma
        h_gamma = h ** (-gamma)
        sk = SecretKey(g_G_p, g_G_q, g_G_r, g_G_s, hs, us, h_gamma, P)
        g_GT = pairing.apply(g_G_p, g_G_p)
        tags = {}
        return cls(securityParam, pairing, params, sk, g_GT, None, tags, \
                   strength)

    def encrypt(self, x: "vector of elements in Zr") -> "ciphertext":
        y = Element.random(self.pairing, Zr)
        z = Element.random(self.pairing, Zr)
        a = Element.random(self.pairing, Zr)
        b = Element.random(self.pairing, Zr)
        S = self.sk.g_G_s**Element.random(self.pairing, Zr)
        S0 = self.sk.g_G_s**Element.random(self.pairing, Zr)
        Rs = []
        for i in range(self.security):
                r1 = self.sk.g_G_r**Element.random(self.pairing, Zr)
                r2 = self.sk.g_G_r**Element.random(self.pairing, Zr)
                Rs.append((r1, r2))
        C = S*self.sk.g_G_p**y
        C0 = S0*self.sk.g_G_p**z
        Cs = []
        for i in range(self.security):
                h1, h2 = self.sk.hs[i]
                u1, u2 = self.sk.us[i]
                i1 = self.sk.g_G_q**(a*x[i])
                i2 = self.sk.g_G_q**(b*x[i])
                c1 = h1**y * u1**z * i1 * Rs[i][0]
                c2 = h2**y * u2**z * i2 * Rs[i][1]
                Cs.append((c1, c2))
        return Ciphertext(C, C0, Cs)

    def genToken(self, v: "description of a predicate") -> "SK_f":
        R = self.sk.g_G_r ** Element.random(self.pairing, Zr)
        R0 = self.sk.g_G_r ** Element.random(self.pairing, Zr)
        Rs = []
        for i in range(self.security):
            # Build r1
            r1 = Element.random(self.pairing, Zr)
            # Build r2
            r2 = Element.random(self.pairing, Zr)
            Rs.append((r1, r2))
        Ss = [(self.sk.g_G_s ** Element.random(self.pairing, Zr), \
               self.sk.g_G_s ** Element.random(self.pairing, Zr)) \
              for i in range(self.security)]
        f1 = Element.random(self.pairing, Zr)
        f2 = Element.random(self.pairing, Zr)
        # K = R * self.sk.h_gamma
        # K0 = R0 * self.sk.h_gamma
        K = R
        K0 = R0
        Ks = []
        for i in range(self.security):
            # Get h1, h2
            h1, h2 = self.sk.hs[i]

            # Get u1, u2
            u1, u2 = self.sk.us[i]

            # Get r1, r2, s1, s2
            r1, r2 = Rs[i]
            s1, s2 = Ss[i]

            # Form the intermediate value
            i1 = h1 ** (-r1)
            i2 = h2 ** (-r2)
            j1 = u1 ** (-r1)
            j2 = u2 ** (-r2)

            # TODO: Investigate potential bug?
            #      Ks = [] for pos in range(self.security):
            K *= i1 * i2
            K0 *= j1 * j2
            K1 = (self.sk.g_G_p ** r1) * (self.sk.g_G_q ** (f1 * v[i]) * s1)
            K2 = (self.sk.g_G_p ** r2) * (self.sk.g_G_q ** (f2 * v[i]) * s2)
            Ks.append((K1, K2))
        return Token(K, K0, Ks)

    def loadSecrets(self, string):
        # lines = string.split("\\n")
        # lines.pop(0)
        # str_sk = ""
        # temp_s = lines.pop(0)
        # while temp_s != "-----END SK-----":
        #     str_sk += temp_s + "\n"
        #     temp_s = lines.pop(0)
        if string != "None\n":
            self.sk = SecretKey.fromStr(self.pairing, string)

if __name__ == "__main__":
    security = 10
    c = MyCryptosystem.new(security, 256)

    secret_object = open('/home/michael/graducatepaper/sswpythonimplement/bbox-master/bitbox/src/secrets')
    secretstr = secret_object.read()
    c.loadSecrets(secretstr)
    secret_object.close()

    encrypt_object = open('/home/michael/graducatepaper/sswpythonimplement/bbox-master/bitbox/src/encrypts')
    encryptstr = encrypt_object.read()
    ct = Ciphertext.fromStr(c.pairing, encryptstr)
    encrypt_object.close()

    # file1_v = []
    # for i in range(security):
    #   file1_v.append(0)
    # file1_v[0] = 4
    # file1_v[1] = -2
    # ct = c.encrypt(file1_v)
    # print("-----------------------------------------------------------------")
    # print(ct)
    # print("-----------------------------------------------------------------")

    file2_v = []
    for i in range(security):
      file2_v.append(0)
    file2_v[0] = 1
    file2_v[1] = 2

    token = c.genToken(file2_v)
    # print(token)

    # print("***********************************")
    # print(ct.Cs[0][0])
    # print(ct.Cs[1][0])
    temp = c.pairing.apply(ct.C, token.K) * c.pairing.apply(ct.C0, token.K0)

    for i in range(security):
        temp = temp * c.pairing.apply(ct.Cs[i][0], token.Ks[i][0])
        temp = temp * c.pairing.apply(ct.Cs[i][1], token.Ks[i][1])

    print(temp)