golang pki library + command line tool
======================================

* simple usage
* support for ECDSA and RSA keys
* reusable golang library

# Usage

```
➜ go get github.com/trusch/pki/pkitool
➜ pkitool init
➜ pkitool issue server my-server
➜ pkitool issue client my-client
➜ pkitool issue ca my-ca
➜ tree
.
└── pki
    ├── ca.crt
    ├── ca.key
    ├── my-client.crt
    ├── my-client.key
    ├── my-server.crt
    ├── my-server.key
    ├── my-ca.crt
    ├── my-ca.key
    └── serial

1 directory, 7 files
```

# Todo

* CRL management
