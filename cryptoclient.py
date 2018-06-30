#!/usr/local/bin/python3
'''
Author:Liam Wadman, Liam.wadman@gmail.com
Purpose: Retreive Decrypt DEK using google KMS. Use DEK to decrypt file

Specify file as an input variable
encrypted files will be output as filename.enc

decrypted files will drop the .enc

This is an envelope encryption implementation. the first 152 bytes of a file (base64 encoded) will be an encrypted DEK. The dek will be slurped off, decrpyted.
Then in turn using the DEK, we will then decrypt the rest of the file. Exciting times?


'''


import argparse
from os import urandom,access
import os
import base64
from Crypto.Cipher import AES
import googleapiclient.discovery
from google.oauth2 import service_account
import filecrypter
import json



def encryptFile(filename,nonce, key,crypto_keys,outfile):
        """
         filename: must be a valid file on the filesystem that your user has READ access to.
         key 16 byte key. if unspecified will generated from urandom.
         crypto_keys: gcp KMS client object
        """
        if key == None:
                key = urandom(16)
        request = crypto_keys.encrypt(
                name=name,
                body={'plaintext': base64.b64encode(key+nonce).decode('ascii')}
                )
        response = request.execute()
        cipherTextKey = response['ciphertext'].encode('ascii')
        
        filecrypter.encrypt_file(key,nonce,cipherTextKey,filename,outfile)
        

def getEDEK(filename):
        """
                filename:encrypted file
        """
        with open(filename, 'rb') as infile:
                edek = infile.read(152)
                infile.close()
                return edek


def decryptFile(filename,crypto_keys,outfile):
        """
                filename: file you want decrypted. preferably end extension with .dec
                crypto_keys:GCP cryptokey client
        """
        
        EDEK = getEDEK(filename) #get the Encrypted DEK out of the file.
        request = crypto_keys.decrypt(
        name=name,
        body={'ciphertext': EDEK.decode('ascii')})
        response = request.execute()
        plaintTxtKey = base64.b64decode(response['plaintext'].encode('ascii'))
        key = plaintTxtKey[:16]
        nonce = plaintTxtKey[16:]
        filecrypter.decrypt_file(key,nonce, filename,outfile)

def readKeyJSON(gcpkey):
        
        with open(gcpkey, 'rb') as infile:
                f = json.load(infile)
        
        return f


#print ciphertext

if __name__ == "__main__":

#################Boring Argument Parsing Zone######################

        parser = argparse.ArgumentParser(description="Envelope Encryption Service backed by GCP KMS")
        parser.add_argument('-i',type=str, action="store", dest="infile",help="absolute path to file you want encrypted or decrypted",nargs='?')
        parser.add_argument('-o',type=str, action="store", dest="outfile",help="optional outfile",nargs='?')
        parser.add_argument('-c',type=str, action="store", dest="credentials",help="GCP json formatted credentials file. defaults to credentials.json",nargs='?')
        parser.add_argument('-k',type=str, action="store", dest="gcpkey",help="text file with the project/location/key_ring_id/crypto_key_id defaults to gcpkey.json",nargs='?')
        parser.add_argument('--encrypt',help="Pass in --encrypt to tell the program to encrypt the file. Specify the file with -i", action="store_true" )
        parser.add_argument('--decrypt',help="Pass in --decrypt to tell the program to decrypt the file. Specify the file with -i", action="store_true" )
        args = parser.parse_args()


        
        if args.encrypt == True and args.decrypt == True:
                print("Stop Being so Indecisive. One or the other")
                print("Error Detail: pick either encrypt or decrpyt")
                exit(1)

        if args.infile == None:
                print("please specify a file to read with -i /path/to/my/file")
                exit(1)
        args.infile = args.infile.strip()
        
        if args.outfile == None and args.decrypt == True:
                print("Please specify an output file location that is writeable")
                print("Detail: No outfile (-o) specified while decrypting")
        args.outfile = args.outfile.strip()

        if access(args.infile,os.R_OK) == False:
                print("we cannot read the infile. Terminating operations")
                exit(1)
        
        if args.outfile != None:
                if os.path.exists(args.outfile) == True:
                        print("it seems like the outfile location already exists. Cowardly refusing to clobber the file, terminating")
                        exit(1)

        if args.credentials != None:
                if access(args.credentials,os.R_OK) == False:
                        print("we cannot read the credentials file. Terminating operations")
                        exit(1)
                else:
                        credentials = args.credentials
        elif args.credentials == None:
                credentials = "credentials.json"

        if args.gcpkey != None:
                if access(args.infile,os.R_OK) == False:
                        print("we cannot read the key location file. Terminating operations")
                        exit(1)
                else:
                        gcpkey = args.gcpkey
        elif args.gcpkey == None:
                gcpkey = "gcpkey.json"




###########################End parsing Args#####################
        
###########################Prepare GCP Client###################

        keystring = readKeyJSON(gcpkey)

        
        credentials = service_account.Credentials.from_service_account_file(credentials)
        kms_client = googleapiclient.discovery.build('cloudkms', 'v1',credentials=credentials)

        name = 'projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(keystring.get("project_id"), keystring.get("location"), keystring.get("key_ring_id"), keystring.get("crypto_key_id"))
        crypto_keys = kms_client.projects().locations().keyRings().cryptoKeys()






#####Execute#####
        if args.encrypt == True:
                encryptFile(args.infile, urandom(16), urandom(16), crypto_keys,args.outfile)
                print("crypto operation seems succesful")
                exit(0)
        
        if args.decrypt == True:
              decryptFile(args.infile, crypto_keys,args.outfile)
              print("de-crypto operation seems succesful")
              exit(0)
        

                

        
        

