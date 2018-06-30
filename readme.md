#CryptoClient.py
======
##A simple envelope encryption script backed by google clouds KMS

This script is a simple spare time project to write an envelope encryption with the Key-Encryption-Key being held in GCP KMS.

With Minimal effort, it could be ported over to another KMS provider.


##How to Operate

```
cryptoclient.py --encrypt -i infile -o outfile [-c GcpCredentialsFile -k gcpkeylocation]


cryptoclient.py --decrypt -i infile -o outfile [-c GcpCredentialsFile -k gcpkeylocation]
```

If no -c is specified, the script will look for credentials.json

If no -k is specified, the script will look for gcpkey.json


##Credentials.json

credentials.json is expected to be the format that is exported from google compute cloud for "service account" credentials.


##Sample gcpkey.json

```
{
    "project_id": "your-gcp-project",
    "location": "location-of-gcp-service",
    "key_ring_id": "your-key-ring-id",
    "crypto_key_id": "the-name-of-your-key"
}
```

##GCP Permissions
The service account used must have access to both the DECRYPT and ENCRYPT methods on a given key.

The ideal role is "Cloud KMS CryptoKey Encrypter/Decrypter"



##Dependency Resolution

pip -r install requirements.txt

This script was tested on both OSX and windows.


##Randomness

Random number generation is performed by python os.urandom, https://docs.python.org/2/library/os.html#miscellaneous-functions


##GCP KMS docs

Please see https://cloud.google.com/kms/






