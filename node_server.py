from hashlib import sha256
import json
import time
import os

from flask import Flask, request, render_template, redirect
import requests



class Block:
    def __init__(self,index,transactions, timestamp,previous_hash,nonce=0):

        self.index = index
        self.transactions = transactions
        self.timestamp= timestamp
        self.previous_hash=previous_hash
        self.nonce = nonce

    def compute_hash(self):
        block_string = json.dumps(self.__dict__,sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

class Blockchain:
    difficulty=2
    def __init__(self):
        self.chain=[]
        self.unconfirmed_transaction= []
        self.gen_block= self.create_genesis_block()
       
        

    def create_genesis_block(self):
        genesis_block=Block(0,[],time.time(),"0")
        genesis_block.hash=genesis_block.compute_hash()
        
        self.chain.append(genesis_block)
        return genesis_block
    
    

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def proof_of_work(block):
        block.nonce=0
        computed_hash=block.compute_hash()

        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce+=1
            computed_hash=block.compute_hash()

        return computed_hash
    

    def add_block(self,block,proof):
        previous_hash= self.last_block.hash
        if previous_hash != block.previous_hash:
            return False
        if not Blockchain.is_valid_proof(block, proof):
            return False
        block.hash=proof
        self.chain.append(block)
        return True

    @classmethod
    def is_valid_proof(self, block, block_hash):
        if block_hash.startswith('0'*Blockchain.difficulty):
            #ss=block.compute_hash()
            return (block_hash.startswith('0'*Blockchain.difficulty) and block_hash== block.compute_hash())

    def add_new_transaction(self,transaction):
        self.unconfirmed_transaction.append(transaction)

    def mine(self):
        if not self.unconfirmed_transaction:
            return False
        last_block=self.last_block

        new_block= Block(index=last_block.index+1,
                         transactions= self.unconfirmed_transaction,
                         timestamp=time.time(),
                         previous_hash=last_block.hash)
        proof= self.proof_of_work(new_block)
        #r= self.save_block(new_block)
        self.add_block(new_block,proof)
        r= self.save_block(new_block)
        self.unconfirmed_transaction=[]
        return new_block.index
   
    def save_block(self, block):

        with open('blockchain.json') as json_file:
            data = json.load(json_file)
        
        data.append(block.__dict__)
        with open('blockchain.json', 'w') as f:
            json.dump(data, f)

        return True


    @classmethod
    def check_chain_validity(cls,chain):
        result=True
        previous_hash="0"

        for block in chain:
            block_hash= block.hash
            delattr(block,"hash")
            if not cls.is_valid_proof(block, block.hash) or previous_hash != block.previous_hash:
                result=False
                break
            block.hash, previous_hash=block_hash,block_hash
            return result


def create_chain_from_dump(chain_dump):
    blockchain=Blockchain()
    for idx,block_data in enumerate(chain_dump):
        block=Block(block_data['index'],
                    block_data['transactions'],
                    block_data['timestamp'],
                    block_data['previous_hash'],
                    block_data['nonce'],)
        proof= block_data['hash']

        if idx==0:
            block.hash=proof
            blockchain.chain[0]= block

        else:
            added= blockchain.add_block(block,proof)
            if not added:
                raise  Exception(" The chain dump is tampered")
       # else:
            #blockchain.chain.append(block)

    return blockchain

def save_peer(peers): 
    stringa = ""
    for peer in peers:
        if stringa == "" :
            stringa = str(peer)
        else:
            stringa = stringa + ',' + str(peer)
    with open('peer.txt', 'w') as f:
            f.write(stringa)
            f.close()
   

def check_peer(peers):
    result = list()
    try:
        with open('peer.txt', 'r') as f:
            read = f.read()
            read = read.replace('[', '')
            read = read.replace(']', '') 
            lista = read.split(',')
            lista2 = list()
            for i in lista:
                i = i.replace("'", "")
                lista2.append(i)
                
                
                
            
    except:
        with open('peer.txt', 'w') as f:
            pass
        lista2 = list()

    for n in peers:
        if n in lista2:
            pass
        else:
            result.append(n)
    f.close()
    result.extend(lista2)    
    save_peer(result)
                
                    



    





app = Flask(__name__)


views = "http://127.0.0.1:5000"
#views = "http://0.0.0.0:5000"

try:
   
    f = open("blockchain.json")
    chain_dump=json.load(f)
    blockchain=create_chain_from_dump(chain_dump)
    f.close()
    
except:
    blockchain=Blockchain()
    chain_data=[]
    for block in blockchain.chain:
        chain_data.append(block.__dict__)

    with open('blockchain.json', 'w') as f:
        json.dump( chain_data, f)
try:
    f = open("peer.txt")
    s= f.read()
    s=s.replace("{","")
    s=s.replace("}","")
    s=s.replace("'","")
    lst= s.split(',')
    peers=set(lst)
    f.close()
    for peer in peers: 
        try:
            response = requests.get(peer +"/chain", timeout=2)
            chain_dump = response.json()['chain']
            blockchain = create_chain_from_dump(chain_dump)
        except:
            continue

except:
    peers=set()








@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data=request.get_json()
    #required_fields=["author","content"]
    required_fields = ["author", "content", "cod_prod", "list_prod", "place_of_work", "tipe_of_author", "info_author","p_iva", "nome_prod" ]
    for field in required_fields:
        if not tx_data.get(field):
            return "invalid transaction data", 404

    tx_data["timestamp"]=time.time()
    blockchain.add_new_transaction(tx_data)
    return "success",201

@app.route('/chain',methods=['GET'])
def get_chain():

    chain_data=[]
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                      "peers": list(peers)})

@app.route('/mine',methods=['GET'])
def mine_unconfirmed_transaction():
    result= blockchain.mine()
    if not result:
        return redirect(views + '/error')
    else:
        chain_length=len(blockchain.chain)
        consensus()
        if chain_length== len(blockchain.chain):
            announce_new_block(blockchain.last_block)

        #return " Block #{} is mined".format(blockchain.last_block.index)
        return redirect(views + "/ok_trans")

@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transaction)

@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Add the node to the peer list
    peers.add(node_address)
    check_peer(peers)

    # Return the consensus blockchain to the newly registered node
    # so that he can sync
    return get_chain()


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    Internally calls the `register_node` endpoint to
    register current node with the node specified in the
    request, and sync the blockchain as well as peer data.
    """
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}

    # Make a request to register with remote node and obtain information
    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        # update chain and the peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        node=response.json()['peers']
        for n in node:
            if n== request.host_url:
                continue
            else:
                peers.add(n)
        
        peers.add(node_address)
          
        check_peer(peers)

        return "Registration successful", 200
    else:
        # if something goes wrong, pass it on to the API response
        return response.content, response.status_code

def consensus ():
    global blockchain
    longest_chain=None
    current_len=len(blockchain.chain)

    for node in peers:
        try:
            response = requests.get('{}/chain'.format(node), timeout=2)
        except:
            continue;    
        
        length= response.json()['length']
        chain= response.json()['chain']
        if length>current_len and blockchain.check_chain_validity(chain):
            current_len=length
            longest_chain=chain
    if longest_chain:
        blockchain=longest_chain
        return True
    return False

@app.route('/add_block', methods=['POST'])
def varify_and_add_block():
    block_data= request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])
    proof= block_data['hash']
    added= blockchain.add_block(block, proof)
    if not added:
        return " the block was discarded by the node", 400
    return "block is added to the chain ", 201

def announce_new_block(block):
    """
    A function to announce to the network once a block has been mined.
    Other blocks can simply verify the proof of work and add it to their
    respective chains.
    """
    for peer in peers:

        try:
            url = "{}add_block".format(peer)
            c = requests.get("{}chain".format(peer), timeout=2)
            headers = {'Content-Type': "application/json"}
            requests.post(url,
                            data=json.dumps(block.__dict__, sort_keys=True),
                            headers=headers)

        except:
            pass


