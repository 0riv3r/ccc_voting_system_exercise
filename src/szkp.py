from random import SystemRandom

# Globals

# Cryptography Public Parameters

# Generator of the finite group
g = 2

# Order of the finite group. A big prime number.
p = 11835969984353354216691437291006245763846242542829548494585386007353171784095072175673343062339173975526279362680161974682108208645413677644629654572794703


def zkp_encrypt_vote(w):
    """
    Gets the witness (secret), and encrypts it.
    The plaintext witness never stored.
    """
    return pow(g, w, p)


class Prover:
    """
    Supposed to be the real voter.
    Should be able to prove that she knows what she had voted for.
    """

    def __init__(self, secret):
        self.s = secret
        self.r = SystemRandom().randrange(p)
        self.a = pow(g, self.r, p)
        return

    def get_commitment(self):
        return self.a

    def prove(self, challenge):
        return self.r + challenge * self.s


class Verifier:
    """
    A verifier instance per vote is added to the server.
    """

    def __init__(self, k):
        self.k = k  # the encrypted vote
        self.c = SystemRandom().randrange(p)  # challenge
        self.a = None  # commitment
        return

    def set_commitment(self, commitment):
        self.a = commitment
        return

    def get_challenge(self):
        return self.c

    def verify(self, proof) -> bool:
        # Checking if g^z == a·k^c(mod p)

        if pow(g, proof, p) == (self.a * pow(self.k, self.c, p)) % p:
            return True
        else:
            return False
