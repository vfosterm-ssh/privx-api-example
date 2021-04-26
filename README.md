## PivX API example

#### Requirements:

```pip3 install requirements.txt```

Create a certificate file in the root directory

```touch cert.pem```

Copy your TLS trust anchor from https://example.com/privx/deployment/api-clients
Paste it into cert.pem

#### Usage:
Fill in the required information into the *.env-example* file and rename it to *.env*. When using user credentials only privx username and privx password is required, when using API client fill everything except Privx username and password is required.
At runtime the script will output a list of roles, users, hosts, and the license, as long as the provided credentials have the privileges to do so.