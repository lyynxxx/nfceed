You need to install the "cryptography" python module to use the script. 

pip install cryptography

Make the files executable with "chmod +x encrypt.py" or use them with the interpreter.

Usage:

./encrypt.py "secret message" "your_password"

or read data from a txt file

./encrypt.py -f secret.txt "your_password" 

test it on the demo file: python3 encrypt.py -f demo_file.txt "valami"


./decrypt.py "your_encrypted_base64_data" "your_password"

or from echo/cat

echo "TGl2ZSBsb25nIGFuZCBwcm9zcGVyICE=" | ./decrypt.py - "mypassword123"

