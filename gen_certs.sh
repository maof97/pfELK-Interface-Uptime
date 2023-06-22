# Create a private key for your Certificate Authority (CA)
openssl genpkey -algorithm RSA -out certs/ca.key -pkeyopt rsa_keygen_bits:2048

# Create a public certificate for your CA
openssl req -x509 -new -nodes -key certs/ca.key -days 3650 -out certs/ca.crt -subj "/CN=pfELK Interfase Uptime CA"

# Create a private key for your server
openssl genpkey -algorithm RSA -out certs/server.key -pkeyopt rsa_keygen_bits:2048

# Create a certificate signing request (CSR) for your server
openssl req -new -key certs/server.key -out certs/server.csr -subj "/CN=pfeiu.pve.lan" -addext "subjectAltName = DNS:pfeiu.pve.lan"

# Use the CA to sign the server's CSR and create a certificate
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 365

# Create a private key for your client
openssl genpkey -algorithm RSA -out certs/client/client.key -pkeyopt rsa_keygen_bits:2048

# Create a certificate signing request (CSR) for your client
openssl req -new -key certs/client/client.key -out certs/client/client.csr -subj "/CN=pfELK Interfase Uptime Client"

# Use the CA to sign the client's CSR and create a certificate
openssl x509 -req -in certs/client/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/client/client.crt -days 365

rm certs/server.csr certs/client/client.csr certs/ca.srl