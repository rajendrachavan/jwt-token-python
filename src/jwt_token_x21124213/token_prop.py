import jwt
from jwt.exceptions import ExpiredSignatureError

#Never mention secret to sign tokens here, this is added here for demonstration purpose
my_secret = 't0k#N$#CR#T' 

#This Method is created to generate a JWT Token
def generateJWTToken(name):
    
    # Payload where user data should be passed in
    payload_data = {
        "sub": "x21124213",
        "name": name,
        "nickname": name[0:3]
    }
    
    #Encoding payload data with secret and HMAC Algorithm
    try:
        token = jwt.encode(
            algorithm='HS256',
            payload=payload_data,
            key=my_secret
        )
        
        return token
        
    except ExpiredSignatureError as error:
        print(f'Unable to encode the token, error: {error}')

# This Method is created to verify/validate the above generated token 
def verifyJWTToken(name, token):
    
    try:
        # Fetching header data to understand which algorithm was used to sign the token
        header_data = jwt.get_unverified_header(token)
        
        # Decoding payload data with the header information by passing in the 
        # original token, secret and header algorithm used to sign the token
        decoded_payload = jwt.decode(
            token,
            key=my_secret,
            algorithms=[header_data['alg'], ]
        )
        
        print('\n Decoded Payload Data: ', decoded_payload)
    
        # Verifying the token belongs to the actual user by comparing it with 
        # the user who requested the verification
        if name == decoded_payload['name']:
            return True
        
        return False

    except ExpiredSignatureError as error:
        print(f'Unable to decode the token, error: {error}')
    
#Testing code here    
if __name__ == '__main__':
    
    name = "Rajendra Chavan"
    
    #Success Scenario
    token = generateJWTToken(name)
    print("\n Generated Token: {}".format(token))

    is_token_valid = verifyJWTToken(name, token)
    print("\n Token valid: {}".format(is_token_valid))