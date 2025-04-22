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