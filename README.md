# 🏢 Supply Chain Blockchain API

This project is a blockchain-based supply chain tracking system implemented using **Flask** and **cryptographic hashing**. It allows secure and transparent tracking of product transactions such as purchases and shipments.

## 📌 Features

- ♲ **Blockchain Ledger**: Stores and verifies product transactions.
- 🔄 **Mining Mechanism**: Uses proof-of-work to validate transactions.
- 🔑 **Digital Signatures**: RSA-based signing and verification.
- 🚛 **Product Tracking**: Retrieve shipment history using blockchain.
- 🔒 **Key Generation**: Generate public-private key pairs.

## 📂 File Structure

```
📆 supply-chain-blockchain
 ├ 📄 app.py           # Main Flask application
 ├ 📄 README.md        # Documentation
 ├ 📄 requirements.txt # Dependencies
```

## 🛠 Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/supply-chain-blockchain.git
   cd supply-chain-blockchain
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the Flask application:

   ```bash
   python app.py
   ```

## 🔗 API Endpoints

### 🔑 Generate RSA Key Pair

```
GET /generate_key
```

**Response:**

```json
{
  "private_key": "-----BEGIN PRIVATE KEY----- ... ",
  "public_key": "-----BEGIN PUBLIC KEY----- ... "
}
```

### 📦 Add Product Transaction

```
POST /add_product
```

**Request JSON:**

```json
{
  "product_name": "Laptop",
  "sender": "Manufacturer",
  "recipient": "Retailer",
  "quantity": 100,
  "transaction_type": "shipment",
  "private_key": "-----BEGIN PRIVATE KEY----- ..."
}
```

**Response:**

```json
{
  "message": "Product transaction recorded and block mined!",
  "block": { ... },
  "signature": "f7a9c8d1..."
}
```

### ♲ Get Blockchain

```
GET /blockchain
```

**Response:**

```json
{
  "chain": [ ... ],
  "length": 5
}
```

### ✅ Verify Transaction Signature

```
POST /verify_signature
```

**Request JSON:**

```json
{
  "public_key": "-----BEGIN PUBLIC KEY----- ...",
  "signature": "f7a9c8d1...",
  "transaction_data": {
    "product_name": "Laptop",
    "sender": "Manufacturer",
    "recipient": "Retailer",
    "quantity": 100,
    "transaction_type": "shipment"
  }
}
```

**Response:**

```json
{
  "message": "Signature is valid!",
  "valid": true
}
```

### 🚚 Track Shipment

```
GET /track_shipment?product_name=Laptop
```

**Response:**

```json
{
  "product_name": "Laptop",
  "transactions": [
    {
      "product_name": "Laptop",
      "sender": "Manufacturer",
      "recipient": "Retailer",
      "quantity": 100,
      "transaction_type": "shipment"
    }
  ]
}
```
