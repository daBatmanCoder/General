# General Repository by daBatmanCoder

## Table of Contents

- [Introduction](#introduction)
- [Contents](#contents)
    - [x25519 Exchange Algorithm](#x25519-exchange-algorithm)
    - [Symmetric Encrypt Decrypt](#Symmetric-encrypt-decrypt)


## Introduction

This repository is a collection of random tests and experiments. It serves as a sandbox for trying out various ideas and concepts. Feel free to explore the different files and folders to see what experiments have been conducted.

## Contents

### x25519 exchange algorithm

This file contains the implementation of the x25519 key exchange algorithm in Python.

The x25519 algorithm is a key agreement protocol that allows two parties to establish a shared secret over an insecure channel. It is based on elliptic curve Diffie-Hellman (ECDH) and uses the Curve25519 elliptic curve.

### Symmetric Encrypt Decrypt

This Python script provides functions for encryption and decryption of data using a password-based key.

The derive_key function generates a cryptographic key from a given password and a salt using the Scrypt key derivation function.

The encrypt_data function encrypts data using the derived key from a password. It generates a random salt and nonce, creates an AES-GCM cipher with the derived key and nonce, and then encrypts the data. It returns the encrypted data, salt, encryption tag, and nonce.

The decrypt_data function decrypts data using the derived key from a password. It creates an AES-GCM cipher with the derived key, nonce, and encryption tag, and then decrypts the data. It returns the decrypted data.

## Getting Started

Just clone.

***
**** 
*****

## License

&copy; All right reserved to JK
