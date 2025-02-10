import hashlib  # Library for cryptographic hash functions
import time  # Library for working with timestamps
import json  # Library for handling JSON data
from flask import Flask, jsonify, request  # Flask modules for web application and API handling
from cryptography.hazmat.primitives import hashes  # For cryptographic hashing
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # For RSA key generation and signing
from cryptography.hazmat.primitives import serialization  # For serializing keys
from cryptography.exceptions import InvalidSignature  # For handling invalid signature exceptions

# Initialize Flask application
app = Flask(__name__)


class SupplyChainBlockchain:
    def __init__(self):
        self.chain = []  # Stores the blockchain (list of blocks)
        self.current_transactions = []  # Temporarily stores transactions to be included in the next block
        # Create the first block (genesis block) with default values
        self.new_block(previous_hash='1', nonce=100, timestamp=int(time.time()))
    
    def new_block(self, previous_hash, nonce, timestamp):
        """
        Create a new block in the blockchain
        """
        block = {
            'index': len(self.chain) + 1,  # Block index (position in the chain)
            'timestamp': timestamp,  # Current timestamp
            'transactions': self.current_transactions,  # Transactions included in the block
            'nonce': nonce,  # Nonce used for proof of work
            'previous_hash': previous_hash,  # Hash of the previous block in the chain
            'merkle_root': self.calculate_merkle_root(self.current_transactions),  # Merkle root of transactions
            'hash': self.hash_block(previous_hash, nonce, timestamp)  # Hash of the current block
        }
        
        self.current_transactions = []  # Clear current transactions after adding them to the block
        self.chain.append(block)  # Add the block to the chain
        return block

    def calculate_merkle_root(self, transactions):
        """
        Calculate the Merkle root of the transactions
        """
        if len(transactions) == 0:
            return "0" * 64  # Return a default Merkle root for empty transaction list
        transaction_hashes = [self.hash_transaction(tx) for tx in transactions]  # Hash each transaction
        while len(transaction_hashes) > 1:  # Combine hashes pairwise until a single root is obtained
            if len(transaction_hashes) % 2 != 0:
                transaction_hashes.append(transaction_hashes[-1])  # Duplicate the last hash if odd number of hashes
            transaction_hashes = [
                self.hash_transaction(transaction_hashes[i] + transaction_hashes[i+1])
                for i in range(0, len(transaction_hashes), 2)
            ]
        return transaction_hashes[0]  # Return the final Merkle root

    def hash_transaction(self, transaction):
        """
        Hash a single transaction
        """
        return hashlib.sha256(json.dumps(transaction, sort_keys=True).encode('utf-8')).hexdigest()  # Hash transaction data

    def hash_block(self, previous_hash, nonce, timestamp):
        """
        Create a SHA-256 hash of a block
        """
        block_string = f"{previous_hash}{nonce}{timestamp}"  # Concatenate block attributes
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()  # Return the hash of the block
    
    ## Abiraam Kesavarajah
    def add_transaction(self, product_name, sender, recipient, quantity, transaction_type):
        """
        Adds a product transaction (purchase, shipment, etc.)
        """
        self.current_transactions.append({
            'product_name': product_name,  # Name of the product
            'sender': sender,  # Sender in the transaction
            'recipient': recipient,  # Recipient in the transaction
            'quantity': quantity,  # Quantity of the product
            'transaction_type': transaction_type  # Type of transaction (e.g., purchase, shipment)
        })

    def mine_block(self):
        """
        Mines a new block by finding a valid nonce
        """
        last_block = self.chain[-1]  # Get the last block in the chain
        last_block_hash = last_block['hash']  # Get its hash
        nonce = 0  # Start nonce at 0
        timestamp = int(time.time())  # Get the current timestamp
        while not self.valid_nonce(last_block_hash, nonce, timestamp):  # Find a valid nonce
            nonce += 1  # Increment nonce
            timestamp = int(time.time())  # Update timestamp for real-time mining
        block = self.new_block(previous_hash=last_block_hash, nonce=nonce, timestamp=timestamp)  # Create the new block
        return block

    def valid_nonce(self, previous_hash, nonce, timestamp):
        """
        Simple proof of work to find a valid nonce
        """
        guess = f"{previous_hash}{nonce}{timestamp}"  # Combine attributes to create a guess
        guess_hash = hashlib.sha256(guess.encode('utf-8')).hexdigest()  # Hash the guess
        return guess_hash[:4] == '0000'  # Check if hash meets difficulty condition (4 leading zeros)

    def get_chain(self):
        """
        Return the full blockchain
        """
        return self.chain  # Return the list of blocks
    

    def sign_transaction(self, private_key, transaction_data):
        """
        Sign the transaction data with the sender's private key
        """
        private_key_obj = serialization.load_pem_private_key(private_key.encode(), password=None)  # Load private key
        transaction_data_hash = hashlib.sha256(json.dumps(transaction_data, sort_keys=True).encode('utf-8')).hexdigest()  # Hash transaction data

        signature = private_key_obj.sign(
            transaction_data_hash.encode(),  # Hash of transaction data
            padding.PKCS1v15(),  # RSA padding scheme
            hashes.SHA256()  # Hashing algorithm
        )
        return signature.hex()  # Return the signature as a hex string

    def verify_signature(self, public_key, signature, transaction_data):
        """
        Verify the signature using the public key and transaction data
        """
        public_key_obj = serialization.load_pem_public_key(public_key.encode())  # Load public key
        transaction_data_hash = hashlib.sha256(json.dumps(transaction_data, sort_keys=True).encode('utf-8')).hexdigest()  # Hash transaction data

        try:
            public_key_obj.verify(
                bytes.fromhex(signature),  # Convert hex signature back to bytes
                transaction_data_hash.encode(),  # Hash of transaction data
                padding.PKCS1v15(),  # RSA padding scheme
                hashes.SHA256()  # Hashing algorithm
            )
            return True  # Signature is valid
        except InvalidSignature:
            return False  # Signature is invalid


# Initialize the supply chain blockchain
blockchain = SupplyChainBlockchain()


@app.route('/generate_key', methods=['GET'])
def generate_key():
    """
    Generates a new RSA key pair (private and public) for use in signing/verification.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Public exponent for the RSA key
        key_size=2048,  # Key size in bits
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # PEM encoding for the private key
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # Traditional OpenSSL format
        encryption_algorithm=serialization.NoEncryption()  # No encryption for this example
    ).decode()

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,  # PEM encoding for the public key
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Public key info format
    ).decode()

    return jsonify({
        'private_key': private_key_pem,  # Return private key
        'public_key': public_key  # Return public key
    })


@app.route('/add_product', methods=['POST'])
def add_product():
    # Get the data from the POST request
    data = request.get_json()  # Parse JSON data from the request
    
    # Extract transaction details
    product_name = data.get('product_name')
    sender = data.get('sender')
    recipient = data.get('recipient')
    quantity = data.get('quantity')
    transaction_type = data.get('transaction_type')  # Could be 'purchase', 'shipment', etc.
    private_key = data.get('private_key')
    
    # Add the product transaction to the blockchain
    blockchain.add_transaction(product_name, sender, recipient, quantity, transaction_type)
    
    # Mine a new block to store the transaction
    block = blockchain.mine_block()
    
    # Sign the transaction with the private key
    signature = blockchain.sign_transaction(private_key, {
        'product_name': product_name,
        'sender': sender,
        'recipient': recipient,
        'quantity': quantity,
        'transaction_type': transaction_type
    })

    # Return success message, block data, and signature
    response = {
        'message': 'Product transaction recorded and block mined!',
        'block': block,
        'signature': signature
    }
    return jsonify(response), 200


@app.route('/blockchain', methods=['GET'])
def get_blockchain():
    # Return the full blockchain
    response = {
        'chain': blockchain.get_chain(),
        'length': len(blockchain.get_chain())
    }
    return jsonify(response), 200
@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    # Get the data from the POST request
    data = request.get_json()

    # Extract public key, signature, and transaction data
    public_key = data.get('public_key')
    signature = data.get('signature')
    transaction_data = data.get('transaction_data')

    # Verify the signature
    is_valid = blockchain.verify_signature(public_key, signature, transaction_data)

    # Return result
    response = {
        'message': 'Signature is valid!' if is_valid else 'Signature is invalid!',
        'valid': is_valid
    }
    return jsonify(response), 200


@app.route('/track_shipment', methods=['GET'])
def track_shipment():
    # Get the product name from the query parameter
    product_name = request.args.get('product_name')
    
    # Find all blocks related to the product
    product_transactions = []
    for block in blockchain.get_chain():
        for tx in block['transactions']:
            if tx['product_name'] == product_name:
                product_transactions.append(tx)
    
    response = {
        'product_name': product_name,
        'transactions': product_transactions
    }
    return jsonify(response), 200


# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)  # Run the app in debug mode for development
