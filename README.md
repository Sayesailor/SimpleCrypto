generate a rsa key test.key, which include private & public keys
we can extraction public key from test.key
-------------------

$openssl genrsa -out test.key 1024

$openssl rsa -in test.key -pubout -out test_pub.key
