# Signing an XML using Self Signed Certificate
Create Self Signed Certificate using PEM format:

`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365`



Create a PKCS#12 store:
`openssl pkcs12 -export -in cert.pem -inkey key.pem -out certstore.p12`



Get Base 64 for certstore.p12 to use in C# code
`base64 ./certstore.p12 --wrap=0`