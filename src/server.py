from he import Paillier


class VotingServer:
    def __init__(self, paillier: Paillier):
        self.paillier = paillier
        self.votes = {}

    def __str__(self):
        return f"Number of votes: {len(self.votes)}"

    def add_vote(self, vote: dict):
        # print(f"\nserver has got vote:\n{vote}")
        self.votes.update(vote)

    def get_number_of_votes(self):
        return len(self.votes)

    def get_aggregated_encrypted_results(self):
        aggregated_encrypted_vote = 1
        for vote in self.votes:
            aggregated_encrypted_vote = (
                aggregated_encrypted_vote * self.votes[vote].get("vote")
            ) % self.paillier.nsqr
        return aggregated_encrypted_vote

    def get_proof(self, voter_id):
        return self.votes[voter_id].get("zk_proof")
        # for vote in self.votes:
        #     if voter_id in vote:
        #         return vote[voter_id]["zk_proof"]
