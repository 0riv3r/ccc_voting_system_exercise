"""
Exercise solution
-----------------
@author: Ofer Rivlin
@mail: ofer.rivlin@intel.com

### Voting Client
- The voting client is responsible for casting votes.
- The client encrypts the vote using Paillier encryption and generates a zero-knowledge proof.
- The client then sends the encrypted vote and the zero-knowledge proof to the voting server.
- The client can also decrypt the aggregated results.

### Homomorphic Encryption

- Chosen Scheme: Paillier Encryption
- Paillier encryption is chosen for this application due to its additive homomorphic property which allows summing encrypted values.
"""

from he import Paillier
from szkp import Verifier, zkp_encrypt_vote


class VotingClient:
    def __init__(self, paillier: Paillier, g: int, p: int):
        self.paillier = paillier  # a Paillier instance
        self.g = g  # generator
        self.p = p  # prime number
        return

    def cast_vote(self, voter_id: int, vote: int) -> dict:
        """
        Casts a vote for a given voter_id.
        The vote is encrypted using Paillier encryption.
        A zero-knowledge verifier is created with the zk-encrypted vote.
        The encrypted vote and the zero-knowledge verifier instance are sent to the voting server.
        """
        # Ensure the vote is either 0 or 1
        if vote not in [0, 1]:
            raise ValueError("Invalid vote. Vote must be 0 or 1.")

        # Creates the Verifier instance (to verify the zero-knowledge proof),
        # and gives it the zk-encrypted vote
        zk_verifier = Verifier(
            k=zkp_encrypt_vote(g=self.g, p=self.p, w=vote), g=self.g, p=self.p
        )

        return {
            voter_id: {
                "he_encrypted_vote": self.paillier.encrypt(
                    vote
                ),  # Encrypt the vote using Paillier encryption
                "zk_verifier": zk_verifier,
            }
        }

    def decrypt_aggregated_results(self, aggregated_encrypted_results):
        return self.paillier.decrypt(aggregated_encrypted_results)
