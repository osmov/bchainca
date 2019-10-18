# bchainca
SNE RP1 Blockchain PKI on Sawtooth

# Run Sawtooth test network

Start the first node:

```
$ docker-compose -f boot-node.yaml up -d
```

Start other node (PoET engine rqured at least three additional nodes:

```
$ docker-compose -f node-0.yaml -f node-1.yaml -f node-2.yaml up -d
```

Each node contains several services: validator, rest-api and set of transaction processors - settings, identity, poet engine, poet validator registry, and bchainca. 

Install Sawtooth core packagies on host machine (for using sawtooth tool to create users and set permissions):

```
$ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD

$ sudo add-apt-repository 'deb [arch=amd64] http://repo.sawtooth.me/ubuntu/bumper/stable xenial universe'

$ sudo apt update

$ apt install sawtooth python3-sawtooth-*
```

Create users transaction signing keys

```
$ sawtooth keygen admin

$ sawtooth keygen user
```

# (Optional) Set permissions

Copy superuser private key generated while starting first node

```
$ mkdir -p ~/.sawtooth/keys

$ sudo chmod a+r /var/lib/docker/volumes/rp1_poet-shared/_data/superuser.*

$ sudo cp /var/lib/docker/volumes/rp1_poet-shared/_data/superuser.* ~/.sawtooth/keys --force
```

Set the permisiions:

```
$ sawtooth identity policy create ca_admin "PERMIT_KEY $(cat ~/.sawtooth/keys/admin.pub)" --key ~/.sawtooth/keys/superuser.priv
$ sawtooth identity role create transactor.transaction_signer.ca_admin ca_admin --key ~/.sawtooth/keys/superuser.priv
```

```
$ sawtooth identity policy create ca_client "PERMIT_KEY $(cat ~/.sawtooth/keys/user.pub)" --key ~/.sawtooth/keys/superuser.priv
$ sawtooth identity role create transactor.transaction_signer.ca_client ca_client --key ~/.sawtooth/keys/superuser.priv
```

# Initialize CA
Create keypairs and CA Root self-sign certificate

```
$ bchainca-cli/python3 cli.py init --username admin
```

# Workflow
Send certificate request

```
$ bchainca-cli/python3 cli.py create COMMON_NAME --username user
```

List requests

```
$ bchainca-cli/python3 cli.py list_approve --username admin
```

Approve request by singer

```
$ bchainca-cli/python3 cli.py approve signer_key --username admin
```

Get list approved requests

```
$ bchainca-cli/python3 cli.py list --username user
```

Get approved certificate by serial number

```
$ bchainca-cli/python3 cli.py get serial_number --username user
```

Get certificate status by serial number

```
$ bchainca-cli/python3 cli.py status serial_number --username user
```

Revoke certificate

```
$ bchainca-cli/python3 cli.py revoke serial_number --username admin
```
# Infrastrcure designs

# Workflow design

