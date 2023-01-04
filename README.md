# Simplified-secure-messaging-
The objective of this computer project is to make you understand the design of an email software secure (inspired by the Signal protocol, used in Signal, but also WhatsApp, Messenger, Google Messages, optional on Skype, etc. )
##Introduction:
The design of secure or "encrypted" messaging software has an important feature:
it must be able to operate asynchronously. Indeed, unlike other use cases, for
example, browsing the Internet, the messaging software must take into account the case where the
communicating users are not connected at the same time; Alice can send a message to
Bob and the latter will receive it much later.
The asynchronous aspect of messaging software is in practice managed by the use of a server which
hosts messages. However, in the case of secure messaging software, or wishes to ensure
that even the server cannot have knowledge of the content of the communications or even that it can
be compromised. Functionally, this amounts to considering that the server is not an entity of
trust.
In order to compensate for the use of a server and to ensure that its compromise cannot compromise the
user messages, two essential mechanisms are implemented: the X3DH (eXtended Triple
Diffie-Hellman) and encryption providing “forward secrecy”.

## How it works?
Key initialization relies primarily on the X3DH ( Asynchronous Key Exchange: eXtended 3 Diffie-Hellman )
Once the communications initialization phase has been completed, Alice and Bob share a key
SK which can be used to exchange messages.
Note that in this project we will distinguish:

• “text” type messages which will be encrypted with RC4 encryption

• the sending of “files” which will be encrypted in blocks with AES-CBC ( You can choose which block mode and the key length )

The specificity of the Signal protocol, which is implemented, is that each message is encrypted with
a separate key. This way of proceeding, is called the “double ratchet” and ensures “forward secrecy”.
The concept of “forward secrecy” is to ensure the continuity of security even if a communication key
is compromised. For this, the principle of implementing keys that "ratchet" is
quite simple and relies on a chain of “Key-Derivation Functions” (KDF).

## Notes:

•The key length used in X3DH is 2048 bit ( You can change it by changing the primary number length "p" )

•The communication is established by the server that stores the public keys and the encrypted data verified by the EL GAMAL signature

•Don't forget to create the csv files in the same directory of the code if you doanloaded only the source code

•KDF used is HMAC256 ( same as Signals )

•Donwload the projet.zip to test and use the message service : it contains the source code with prepared csv files in a single folder

## Key words:

• eXtended 3 Diffie-Hellman

•AES encryption

•RC4 encryption

•Double ratchet

•El GAMAL signature

•Forward secrecy

•HMAC 256

•Message service

•Cryptology

## References:
1) H-KDF logic : https://fr.wikipedia.org/wiki/HMAC
2) Double Ratchet logic : https://nfil.dev/coding/encryption/python/double-ratchet-example/
3) AES, dans Github : https://github.com/octopius/slowaes
4) DH : https://pypi.org/project/py-diffie-hellman
