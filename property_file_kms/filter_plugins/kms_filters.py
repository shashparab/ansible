import boto3
import base64

kms = boto3.client('kms')

def kms_decrypt(ciphertext):
    return kms.decrypt(CiphertextBlob=base64.b64decode(ciphertext)).get('Plaintext')

def kms_encrypt(plaintext, key):
    return base64.b64encode(kms.encrypt(KeyId=key,Plaintext=plaintext).get('CiphertextBlob'))

def kms_encrypt_modified(plaintext, password_key, key):
    f = open( 'files/kms_encrypted_values.yaml', 'a' )
    f.write( password_key + ': ' + base64.b64encode(kms.encrypt(KeyId=key,Plaintext=plaintext).get('CiphertextBlob')) + '\n' )
    f.close()

class FilterModule(object):
    def filters(self):
        return { 'kms_encrypt_modified': kms_encrypt_modified, 'kms_encrypt': kms_encrypt, 'kms_decrypt': kms_decrypt }
