# Handshake

According to the assignment the application performs handshake over peer network protocol using tcp connection. No btc package was used for the implementation. I have used it only for testing and to make sure handshake was successful. I used about two days (12 hours were not enough) and looked into peer library to understand the encoding.

## Prerequisites

Before running the application or tests, ensure that you have Go installed on your system. You can download and install it from [https://golang.org/dl/](https://golang.org/dl/).

## Running the Application

Clone and run the handshake with the following parameters: 'newtork' which must be either 'main' or 'sim' for mainnet and simnet correspondingly, node full address and protocol version. See the example below:

   ```bash
   git clone git@github.com:shotasilagadze/handshake.git
   cd handshake
   go run main.go main 35.175.179.123:18333 70017
   ```

## Running tests
    
    go test ./...
