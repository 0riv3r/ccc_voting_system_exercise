

"""

gmpy2:
pip install gmpy2
gmpy2 is an optimized, C-coded Python extension module that supports fast multiple-precision arithmetic. 
gmpy2 is based on the original gmpy module. gmpy2 adds support for correctly rounded multiple-precision 
real arithmetic (using the MPFR library) and complex arithmetic (using the MPC library).

"""
import random  
import gmpy2  
 

class Paillier:  
    def __init__(self, key_size=512):  
        self.key_size = key_size  
        self.generate_keys()  
  
    def generate_keys(self):  
        p = gmpy2.next_prime(gmpy2.mpz_urandomb(gmpy2.random_state(random.getrandbits(32)), self.key_size))  
        q = gmpy2.next_prime(gmpy2.mpz_urandomb(gmpy2.random_state(random.getrandbits(32)), self.key_size))  
        n = p * q  
        self.n = n  
        self.nsqr = n * n  
        self.g = n + 1  
        self.lambda_ = gmpy2.lcm(p - 1, q - 1)  
        self.mu = gmpy2.invert(self.lambda_, n)  
  
    def encrypt(self, plaintext):  
        n = self.n  
        r = gmpy2.mpz_random(gmpy2.random_state(random.getrandbits(32)), n)  
        c = gmpy2.powmod(self.g, plaintext, self.nsqr) * gmpy2.powmod(r, n, self.nsqr) % self.nsqr  
        return int(c)  
  
    def decrypt(self, ciphertext):  
        x = gmpy2.powmod(ciphertext, self.lambda_, self.nsqr) % self.nsqr - 1  
        plaintext = (x // self.n) * self.mu % self.n  
        return int(plaintext)  
  
def main():
  paillier = Paillier()  
  public_key = paillier.n  
  private_key = (paillier.lambda_, paillier.mu) 

  print(f'Public Key: {public_key}')
  print(f'Private Key: {private_key}') 


if __name__ == '__main__':
    main()
