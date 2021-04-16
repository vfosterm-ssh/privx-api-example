## PivX API example

#### Requirements:

```pip3 install requirements.txt```

Create a certificate file in the root directory

```touch cert.pem```

Copy your TLS trust anchor from https://example.com/privx/deployment/api-clients
Paste it into cert.pem

#### Usage:
Fill in the required information into the global variables at the top of the script, into either of the 2 authentication methods then run the script.
The script will output a list of roles, users, hosts, and the license, as long as the provided credentials have the privileges to do so.