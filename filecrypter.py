#!/usr/local/bin/python3

import os, sys
from os import urandom
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

blobsize = 256 #This variable controls the file read/write bytes per operation
#size must be % 16 - 0
#interestingly, it seems to complain about a size >256


def encrypt_file(key,nonce,cipherTextKey,filename,out_filename):
    """
    key = 16 character AES key. Bring your own entropy!
    cipherTextKey. Key formatted as ciphertext+base64. This is necesarry to cleanly insert it into the file.
    filename = name of the file (absolute path) you want encrypted. encrypted output will be saved to filename.enc
    """
    


    encryptor = AES.new(key, AES.MODE_GCM,nonce=nonce)
    try:
        with open(filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(cipherTextKey)

                try:
                    while True:
                        chunk = infile.read(blobsize-1)
                        if len(chunk) == 0:
                            break
                        chunk = pad(chunk,blobsize,style='pkcs7')
                        outfile.write(encryptor.encrypt(chunk))
                except:
                    print("Unexpected error: ", sys.exc_info()[0])
                    raise


    except:
        print("Unexpected error: ", sys.exc_info()[0])  
        raise

def decrypt_file(key,nonce, filename,out_filename):
   
  


    with open(filename, 'rb') as infile:
        infile.read(152) #discard the encrypted DEK and 8 byte preamble
        decryptor = AES.new(key, AES.MODE_GCM,nonce=nonce)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(blobsize)
                if len(chunk) == 0:
                    break
                outfile.write(unpad(decryptor.decrypt(chunk),blobsize,style="pkcs7"))




if __name__ == "__main__":
    print("Don't call this lib directly. its mean to be called by cryptoclient.py")
    quit(1)