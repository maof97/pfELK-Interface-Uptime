# Create a private key for your Certificate Authority (CA)
openssl genpkey -algorithm RSA -out ca.key -pkeyopt rsa_keygen_bits:2048

# Create a public certificate for your CA
openssl req -x509 -new -nodes -key ca.key -days 3650 -out ca.crt -subj "/CN=pfELK Interfase Uptime CA"

# Create a private key for your server
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048

# Create a certificate signing request (CSR) for your server
openssl req -new -key server.key -out server.csr -subj "/CN=pfeiu.pve.lan" -addext "subjectAltName = DNS:pfeiu.pve.lan"

# Use the CA to sign the server's CSR and create a certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Create a private key for your client
openssl genpkey -algorithm RSA -out client.key -pkeyopt rsa_keygen_bits:2048

# Create a certificate signing request (CSR) for your client
openssl req -new -key client.key -out client.csr -subj "/CN=pfELK Interfase Uptime Client"

# Use the CA to sign the client's CSR and create a certificate
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
