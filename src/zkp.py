
import random
import hashlib

class ZeroKnowledgeProof:  
    def __init__(self, n):  
        self.n = n  
        self.q = (n - 1) // 2  
  
    def generate_proof(self, vote, g):  
        h = random.randint(1, self.q)  # Random value for ZKP  
        a = pow(g, h, self.n)  
        e = int(hashlib.sha256(f'{a}'.encode()).hexdigest(), 16) % self.q  
        s = (h + e * vote) % self.q  
        return (a, e, s)  
  
    def verify_proof(self, proof, g, v):  
        a, e, s = proof  
        gv = pow(g, v, self.n)  
        gs = pow(g, s, self.n)  
        ae = (a * pow(gv, e, self.n)) % self.n  
        return e == int(hashlib.sha256(f'{ae}'.encode()).hexdigest(), 16) % self.q  
  

def main():

  public_key = 162226229347756391271493051852354917401090038039683320680804543042649535583686206083630572713317750229429435381913417701326535023164813483611251464422652784109615338949060378037516070621171510493670038973397665757380301426245999887571375917399824781541707981283414449931124595977510184265009967092100960059547

  secure_zk = ZeroKnowledgeProof(public_key)  
  print(f"secure_zk: {secure_zk}")

if __name__ == '__main__':
    main()