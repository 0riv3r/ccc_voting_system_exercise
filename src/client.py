from he import Paillier
from szkp import Verifier, zkp_encrypt_vote


class VotingClient:
    def __init__(self, paillier: Paillier, generator: int = 2):
        self.paillier = paillier
        self.generator_g = generator

    def cast_vote(self, voter_id: int, vote: int):
        # Ensure the vote is either 0 or 1
        if vote not in [0, 1]:
            raise ValueError("Invalid vote. Vote must be 0 or 1.")

        zk_verifier = Verifier(k=zkp_encrypt_vote(w=vote))

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
