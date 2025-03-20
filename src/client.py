from he import Paillier
from szkp import Prover, Verifier, zkp_encrypt_vote

from server import VotingServer

votes = [(1, 1), (2, 0), (3, 1)]


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


def main():

    # Setup the Paillier cryptosystem and secure ZK proofs
    paillier = Paillier()
    generator_g = 2

    # Setup the client and server
    client = VotingClient(paillier, generator_g)
    server = VotingServer(paillier)

    # Cast all votes
    for voter_id, vote in votes:
        vote = client.cast_vote(voter_id, vote)
        server.add_vote(vote)

    # Number of votes
    print(server)  # Number of votes: len(votes)
    assert server.get_number_of_votes() == len(votes)

    # Get voting final results
    aggregated_encrypted_results = (
        server.get_aggregated_encrypted_results()
    )  # Aggregated encrypted results
    final_tally = client.decrypt_aggregated_results(
        aggregated_encrypted_results
    )  # Decrypted final tally
    print(f"Final Decrypted Tally: {final_tally}")  # Final Decrypted Tally: 2

    print(
        "\n" + "-------- Votes Verifications using Sigma ZKP protocol --------" + "\n"
    )

    """ Verify votes using Sigma ZKP protocol
    The system checks for voting frauds
    Does the voter know what she voted for? 
    """

    for vote in votes:
        voter_id, cleartext_vote = vote
        print(f"\nVoter ID: {voter_id}, ", end="")
        zk_verifier = server.votes[voter_id]["zk_verifier"]
        zk_prover = Prover(secret=cleartext_vote)

        commitment = zk_prover.get_commitment()
        zk_verifier.set_commitment(commitment)
        challenge = zk_verifier.get_challenge()
        proof = zk_prover.prove(challenge)
        if zk_verifier.verify(proof):
            print("Proof Accepted!")
        else:
            print("Proof Rejected!")


if __name__ == "__main__":
    main()
