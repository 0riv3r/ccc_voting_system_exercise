from szkp import Prover, Verifier, zkp_encrypt_vote

# from random import SystemRandom


# main

print("\n" + "-------- Sigma ZKP protocol example --------" + "\n")

encrypted_vote = zkp_encrypt_vote(w=1)

prover = Prover(secret=1)
verifier = Verifier(k=encrypted_vote)

commitment = prover.get_commitment()
verifier.set_commitment(commitment)

challenge = verifier.get_challenge()
proof = prover.prove(challenge)
verifier.verify(proof)
