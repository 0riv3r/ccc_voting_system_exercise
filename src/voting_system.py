from he import Paillier
from szkp import Prover
from client import VotingClient
from server import VotingServer
import subprocess
import re

# The votes that were casted
casting_votes = {1: 1, 2: 0, 3: 1, 4: 0, 5: 0, 6: 1, 7: 1, 8: 1, 9: 0, 10: 1}

# The preferences of the REAL voters
voters_preferences = {1: 1, 2: 0, 3: 1, 4: 0, 5: 0, 6: 1, 7: 0, 8: 1, 9: 0, 10: 1}


# Generate a random prime number
# The output is in the file 'dhparams' at the same path
# openssl dhparam -text -out dhparams 512
def generate_prime() -> tuple:
    p = None  # Order of the finite group. A big prime number.
    g = None  # Generator of the finite group
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

    return g, p


def main():

    # Setup the Paillier cryptosystem and secure ZK proofs
    paillier = Paillier()

    generator, prime = generate_prime()

    # Setup the client and server
    client = VotingClient(paillier, generator, prime)
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
        zk_prover = Prover(g=generator, p=prime, secret=cleartext_vote)

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
