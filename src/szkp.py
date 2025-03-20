import subprocess
from random import SystemRandom
import re

# Globals

p = None
# Generator of the finite group
g = None


# Generate a random prime number
# The output is in the file 'dhparams' at the same path
# openssl dhparam -text -out dhparams 512
def generate_prime():
    global p
    global g
    subprocess.run(["openssl", "dhparam", "-text", "-out", "dhparams", "512"])
    # Read the content of the file "dhparams"
    with open("dhparams", "r") as file:
        dhparams_text = file.read()

    # Extract the multi-line hexadecimal prime number between "P:" and "G:"
    match = re.search(r"P:\s*([\s\S]*?)\s*G:", dhparams_text, re.IGNORECASE)
    if match:
        hex_number = match.group(1).replace(":", "").replace("\n", "").replace(" ", "")
        # print(f"Hexadecimal prime number: {hex_number}")

        # Convert the hexadecimal prime number to a decimal number
        p = int(hex_number, 16)
        # print(f"The prime number: {p}")
    else:
        print("No match found")

    # Extract the generator number
    g_match = re.search(r"G:\s*(\d+)\s*\(0x2\)", dhparams_text)
    if g_match:
        g = int(g_match.group(1))
        # print(f"Integer number from G: {g}")
    else:
        print("No match found for integer number in G:")


# Cryptography Public Parameters


# Order of the finite group. A big prime number.
# p = 11835969984353354216691437291006245763846242542829548494585386007353171784095072175673343062339173975526279362680161974682108208645413677644629654572794703
# p = 9423829478468623059013555648754247141819931845621509004201969629900343558690842612217899443889538899047617212780362537113618964143099463264674237944163119


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


generate_prime()


def main():
    generate_prime()


if __name__ == "__main__":
    main()
