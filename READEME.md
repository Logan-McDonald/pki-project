# PKI Project Write-up

## Process to run application

1. Run "generate_keys.py"
    - To start off, we need to generate the server and client public and private keys.
    - Open a terminal and navigate to the project directory and run `python generate_keys.py`
    - This should create a directory and store the keys into it, note if you run this again it will just overwrite the current keys already in it.

2. Run "server.py"
    - Now we need to establish the server for the clients to connect to.
    - Run `python server.py` to get the server up and running.
    - You should see two messages in the CLI:
        - `[*] Starting server...`
        - `[*] Listening on 127.0.0.1:65432` 

3. Now establish a client by running "client.py"
    - In order to connect a client to the server we established we need to establish a new terminal, navigate to the project directory, and run the command `python client.py`
    - In the server terminal window, it should acknowledge the client connection
    - A window should also pop up with the GUI for the chat room

4. Next, you need to add another client by opening another terminal window
    - Run `python client.py` in the new terminal
    - Check to make sure the server CLI recognizes the new client connection
    - A second window should pop up and now you can message the other connected client(s) freely and securely.

## Documentation

#### Introduction
In this project, we designed a secure server to client chatroom that utilizes socket programming as well as encryption. The hardest part of this project was integrating the Public key infrustructure with RSA and AES in order to give our chat program the level of security it needed. We were able to develop a system that had provided both higher safetly and security from future attackers.
#### Key Generation
Firstly, we created the RSA key pairs of the upcoming server and clients. Every memer entering the chat room possesses a public and private key that is created from the PyCrypodome library. We utilized the public key to encrypt the AES session keys and the private keys to decrypt them. They were stored in the `.pem` format, including some like `server_private.pem` and `client_public.pem`.
#### Encryption Process
When a message is being sent in our messaging app, the message is first encrypted using a randomly selected AES key to ensure confidentiality. Then AES key is encrypted using the arriving RSA's public key and both AES and RSA encrypted keys are being transmitted. Receivers client then decrypts the AES key using their private key and then messages are decrypted using that final key.
#### Socket Communication
We caused the server to use TCP socket then bind IP and port, then just listen for connections to handle. All clients connecting to the server are using a TCP socket. We also had to implement threading in this project which we never did before. It was an amazing experience and now the server can handle more than one client at a time.
#### Error Handling

#### Challenges