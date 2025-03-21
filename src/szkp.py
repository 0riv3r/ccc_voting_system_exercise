from random import SystemRandom


def zkp_encrypt_vote(g, p, w):
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

    def __init__(self, g, p, secret):
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

    def __init__(self, k, g, p):
        self.k = k  # the encrypted vote
        self.c = SystemRandom().randrange(p)  # challenge
        self.a = None  # commitment
        self.g = g
        self.p = p
        return

    def set_commitment(self, commitment):
        self.a = commitment
        return

    def get_challenge(self):
        return self.c

    def verify(self, proof) -> bool:
        # Checking if g^z == a·k^c(mod p)

        if (
            pow(self.g, proof, self.p)
            == (self.a * pow(self.k, self.c, self.p)) % self.p
        ):
            return True
        else:
            return False
