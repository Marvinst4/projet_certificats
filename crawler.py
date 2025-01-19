import requests
from bs4 import BeautifulSoup
import re
import sqlite3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os
from concurrent.futures import ThreadPoolExecutor
from functools import partial

def download_pem(cert_id, output_filename):
    url = f'https://crt.sh/?d={cert_id}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open(output_filename, "wb") as file:
                file.write(response.content)
            print(f"Certificat téléchargé et enregistré sous le nom : {output_filename}")
        else:
            print(f"Erreur lors du téléchargement : {response.status_code}")
    except Exception as e:
        print(f"Une erreur est survenue : {e}")

def extract_data(file_url):
    with open(file_url, 'rb') as cert_file:
        cert_data = cert_file.read()

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    version = str(cert.version)
    serial_number = cert.serial_number
    signature_algorithm = cert.signature_algorithm_oid._name
    not_valid_before = cert.not_valid_before.isoformat()
    not_valid_after = cert.not_valid_after.isoformat()

    issuer = cert.issuer
    issuer_cn = None
    for attribute in issuer:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            issuer_cn = attribute.value
            break

    subject = cert.subject
    subject_cn = None
    for attribute in subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            subject_cn = attribute.value
            break

    public_key = cert.public_key()
    modulus = public_key.public_numbers().n
    exponent = public_key.public_numbers().e

    insert_data(version, serial_number, signature_algorithm, not_valid_before, 
                not_valid_after, issuer_cn, subject_cn, modulus, exponent)

def insert_data(version, serial_number, signature_algorithm, not_valid_before, 
                not_valid_after, issuer_cn, subject_cn, modulus, exponent):
    conn = sqlite3.connect("certificates.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO certificates (
        version, serial_number, signature_algorithm, not_valid_before, not_valid_after, 
        issuer_cn, subject_cn, modulus, exponent
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (version, str(serial_number), signature_algorithm, not_valid_before, 
          not_valid_after, issuer_cn, subject_cn, str(modulus), exponent))

    conn.commit()
    conn.close()

def download_and_extract(cert_id):
    output_filename = f"certificats/{cert_id}.pem"
    
    if not os.path.exists(output_filename):
        download_pem(cert_id, output_filename)

    extract_data(output_filename)
    
print("Démarrage des téléchargements...")
for cert_id in range(1, 100001):
    try:
        download_and_extract(cert_id)
    except Exception as e:
        print(f"Erreur inattendue lors du traitement de l'ID {cert_id} : {e}")

print("Téléchargements terminés.")