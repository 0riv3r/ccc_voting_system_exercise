from he import Paillier
from zkp import ZeroKnowledgeProof
from server import VotingServer


class VotingClient:
    def __init__(self, paillier: Paillier, generator: int = 2):
        self.paillier = paillier
        self.zk = ZeroKnowledgeProof(paillier.n)
        self.generator_g = generator

    def cast_vote(self, voter_id: int, vote: int):
        # Ensure the vote is either 0 or 1
        if vote not in [0, 1]:
            raise ValueError("Invalid vote. Vote must be 0 or 1.")

        # Encrypt the vote using Paillier encryption
        encrypted_vote = self.paillier.encrypt(vote)

        # Generate zero-knowledge proof for vote validity
        zk_proof = self.zk.generate_proof(vote, self.generator_g)

        return {voter_id: {"vote": encrypted_vote, "zk_proof": zk_proof}}

    def decrypt_aggregated_results(self, aggregated_encrypted_results):
        return self.paillier.decrypt(aggregated_encrypted_results)


def main():
    # Setup the Paillier cryptosystem and secure ZK proofs
    paillier = Paillier()
    generator_g = 2
    client = VotingClient(paillier, generator_g)
    server = VotingServer(paillier)

    votes = [(1, 1), (2, 0), (3, 1)]
    for voter_id, vote in votes:
        vote = client.cast_vote(voter_id, vote)
        server.add_vote(vote)

    print(server)  # Number of votes: len(votes)
    assert server.get_number_of_votes() == len(votes)

    aggregated_encrypted_results = (
        server.get_aggregated_encrypted_results()
    )  # Aggregated encrypted results
    final_tally = client.decrypt_aggregated_results(
        aggregated_encrypted_results
    )  # Decrypted final tally
    print(f"Final Decrypted Tally: {final_tally}")  # Final Decrypted Tally: 2

    voter_3_proof = server.get_proof(3)
    print(f"Voter 3 Zero-Knowledge Proof: {voter_3_proof}")
    is_valid = client.zk.verify_proof(voter_3_proof, generator_g, 1)
    print(
        f"Voter 3 Zero-Knowledge Proof Valid: {is_valid}"
    )  # Voter 1 Zero-Knowledge Proof Valid: True


if __name__ == "__main__":
    main()
