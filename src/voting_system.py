from he import Paillier
from szkp import Prover
from client import VotingClient
from server import VotingServer

# The votes that were casted
casting_votes = {1: 1, 2: 0, 3: 1, 4: 0, 5: 0, 6: 1, 7: 1, 8: 1, 9: 0, 10: 1}

# The preferences of the REAL voters
voters_preferences = {1: 1, 2: 0, 3: 1, 4: 0, 5: 0, 6: 1, 7: 0, 8: 1, 9: 0, 10: 1}


def main():

    # Setup the Paillier cryptosystem and secure ZK proofs
    paillier = Paillier()
    generator_g = 2

    # Setup the client and server
    client = VotingClient(paillier, generator_g)
    server = VotingServer(paillier)

    # Cast all votes
    for voter_id, vote in casting_votes.items():
        vote = client.cast_vote(voter_id, vote)
        server.add_vote(vote)  # send the encrypted vote to the server

    print("\n" + "------------------- Voting Results --------------------------" + "\n")
    # Number of votes
    print(server)  # Number of votes: len(votes)
    assert server.get_number_of_votes() == len(casting_votes)

    # Get voting final results
    aggregated_encrypted_results = (
        server.get_aggregated_encrypted_results()
    )  # Aggregated encrypted results
    final_tally = client.decrypt_aggregated_results(
        aggregated_encrypted_results
    )  # Decrypted final tally
    print(f"\nFinal Decrypted Tally: {final_tally}")  # Final Decrypted Tally: 2

    print("\n\n" + "-------- Votes Verifications using Sigma ZKP protocol --------")

    """ Verify votes using Sigma ZKP protocol
    The system checks for voting frauds
    Does the voter know what she voted for?
    """
    verification = True
    for voter_id, cleartext_vote in voters_preferences.items():
        zk_verifier = server.votes[voter_id]["zk_verifier"]
        zk_prover = Prover(secret=cleartext_vote)

        commitment = zk_prover.get_commitment()
        zk_verifier.set_commitment(commitment)
        challenge = zk_verifier.get_challenge()
        proof = zk_prover.prove(challenge)
        if zk_verifier.verify(proof) == False:
            verification = False
            print(f"\nVoter ID ({voter_id}): Proof Rejected!")

    if verification:
        print("\nAll votes verified successfully!")
    else:
        print("\nSome votes verification failed!")

    print(
        "\n\n" + "--------------------------------------------------------------" + "\n"
    )


if __name__ == "__main__":
    main()
