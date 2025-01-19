import requests
from bs4 import BeautifulSoup
import re
import sqlite3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import os
from concurrent.futures import ThreadPoolExecutor
from functools import partial

def scrape_crt_sh(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        outer_table = soup.find_all('table')[1] 
        cert_table = outer_table.find('table') 

        if not cert_table:
            print("Aucun tableau contenant les certificats trouvé sur la page.")
            return []

        rows = cert_table.find_all('tr')
        cert_ids = [] 
      
        for row in rows[2:]:  
            cols = row.find_all('td')
            if len(cols) >= 4:  
                crt_id = cols[0].text.strip()
                cert_ids.append(crt_id)  
        return cert_ids

    except Exception as e:
        print(f"Erreur : {e}")
        return []

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

print("Récupération des ids des certificats...")
url = "https://crt.sh/?identity=%25&iCAID=0001"
cert_ids = scrape_crt_sh(url)


print("Démarrage des téléchargements...")
failed_ids = []
for cert_id in cert_ids:
    try:
        download_and_extract(cert_id)
    except Exception as e:
        print(f"Erreur inattendue lors du traitement de l'ID {cert_id} : {e}")
        failed_ids.append(cert_id)
print("Téléchargements terminés.")