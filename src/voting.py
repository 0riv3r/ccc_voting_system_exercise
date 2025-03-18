

from Paillier import Paillier
from zkp import ZeroKnowledgeProof

def cast_vote(vote, paillier, zk, g):  
    if vote not in [0, 1]:  
        raise ValueError("Invalid vote. Vote must be 0 or 1.")  
        
    # Encrypt the vote using Paillier encryption  
    encrypted_vote = paillier.encrypt(vote)  
        
    # Generate zero-knowledge proof for vote validity  
    zk_proof = zk.generate_proof(vote, g)  
        
    return encrypted_vote, zk_proof 
 

def aggregate_votes(encrypted_votes, paillier):  
    aggregated_encrypted_vote = 1  
    for vote in encrypted_votes:  
        aggregated_encrypted_vote = (aggregated_encrypted_vote * vote) % paillier.nsqr  
    return aggregated_encrypted_vote  


def decrypt_aggregated_vote(aggregated_encrypted_vote, paillier):  
    return paillier.decrypt(aggregated_encrypted_vote)  


def verify_all_proofs(encrypted_votes, zk_proofs, g, zk, paillier):  
    for vote, proof in zip(encrypted_votes, zk_proofs):  
        vote_value = paillier.decrypt(vote)  # Decrypt to get the vote for verification  
        if not zk.verify_proof(proof, g, vote_value):  
            return False  
    return True  


def main():  
    # Setup the Paillier cryptosystem and secure ZK proofs  
    paillier = Paillier()  
    secure_zk = ZeroKnowledgeProof(paillier.n)  
    generator_g = 2  
    
    # Example votes cast by different voters (1 or 0)  
    votes = [1, 0, 1, 1, 0, 1]  
    casted_votes = [cast_vote(vote, paillier, secure_zk, generator_g) for vote in votes]  
    encrypted_votes, zk_proofs = zip(*casted_votes)  
    
    # Display the encrypted votes and ZK proofs  
    print(f'Encrypted Votes: {encrypted_votes}')  
    print(f'Zero-Knowledge Proofs: {zk_proofs}')  
    
    # Aggregate the encrypted votes using Paillier's homomorphic property  
    aggregated_encrypted_vote = aggregate_votes(encrypted_votes, paillier)  
    print(f'Aggregated Encrypted Vote: {aggregated_encrypted_vote}')  
    
    # Decrypt the aggregated vote to get the final tally  
    final_tally = decrypt_aggregated_vote(aggregated_encrypted_vote, paillier)  
    print(f'Final Decrypted Tally: {final_tally}')  
    
    # Verify the zero-knowledge proofs for all votes  
    all_proofs_valid = verify_all_proofs(encrypted_votes, zk_proofs, generator_g, secure_zk, paillier)  
    print(f'All Zero-Knowledge Proofs Valid: {all_proofs_valid}')  
    
if __name__ == "__main__":  
    main()  