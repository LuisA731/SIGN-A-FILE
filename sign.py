from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os
import sys




def generate_keys(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    print(f" Llaves generadas:")
    print(f"     Privada → {private_key_path}")
    print(f"     Pública → {public_key_path}")




def sign_file(file_path, private_key_path="private_key.pem", signature_path=None):
    
    if not os.path.exists(file_path):
        print(f" Archivo no encontrado: {file_path}")
        sys.exit(1)

    if signature_path is None:
        signature_path = file_path + ".sig"

    
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    
    with open(file_path, "rb") as f:
        data = f.read()

    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(signature_path, "wb") as f:
        f.write(signature)

    print(f" Archivo firmado exitosamente.")
    print(f"     Archivo   → {file_path}")
    print(f"     Firma     → {signature_path}")




def verify_file(file_path, public_key_path="public_key.pem", signature_path=None):
    
    if signature_path is None:
        signature_path = file_path + ".sig"

    if not os.path.exists(file_path):
        print(f"[ERROR] Archivo no encontrado: {file_path}")
        sys.exit(1)

    if not os.path.exists(signature_path):
        print(f"[ERROR] Archivo de firma no encontrado: {signature_path}")
        sys.exit(1)

    # Cargar llave pública
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )

   
    with open(file_path, "rb") as f:
        data = f.read()

    with open(signature_path, "rb") as f:
        signature = f.read()

   
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(" VERIFICACIÓN EXITOSA: El archivo es auténtico y no ha sido modificado.")
        return True
    except Exception:
        print(" VERIFICACIÓN FALLIDA: La firma NO es válida. El archivo pudo haber sido modificado o corrompido.")
        return False






if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "generate":
        generate_keys()

    elif command == "sign":
        if len(sys.argv) < 3:
            print(" Debes especificar el archivo a firmar.")
            sys.exit(1)
        file_path    = sys.argv[2]
        priv_key     = sys.argv[3] if len(sys.argv) > 3 else "private_key.pem"
        sig_path     = sys.argv[4] if len(sys.argv) > 4 else None
        sign_file(file_path, priv_key, sig_path)

    elif command == "verify":
        if len(sys.argv) < 3:
            print(" Debes especificar el archivo a verificar.")
            sys.exit(1)
        file_path    = sys.argv[2]
        pub_key      = sys.argv[3] if len(sys.argv) > 3 else "public_key.pem"
        sig_path     = sys.argv[4] if len(sys.argv) > 4 else None
        verify_file(file_path, pub_key, sig_path)

    else:
        print(f" Comando desconocido: '{command}'")
        sys.exit(1)
