# RIOT OS Crypto tutorials

These tutorials are available in the following languages: **:gb: English (WIP)** | [:de: German](./README_de.md)

The following tutorials explain how to use different crypto algorithms on the IoT operating system RIOT.
This is a project assignment for the course "IT Security 2" at the [Stuttgart University of Applied Sciences ("Hochschule für Technik Stuttgart")](https://www.hft-stuttgart.de/).

The tutorials are divided into three chapters:

# [Chapter 1: Basics](Tutorials/Chapter_1_Basics)

Chapter 1 provides basic knowledge about RIOT and how to write and run executable programs with RIOT.

## [Part 1: Installation](Tutorials/Chapter_1_Basics/01_Installation_de.md) (:de: only)

Part 1 describes the RIOT installation process as well as the minimum requirements.
We focus on mainly using RIOT under Linux.

## [Part 2: Program structure](Tutorials/Chapter_1_Basics/02_ProgramStructure_de.md) (:de: only)

Part 2 describes the basic structure of a minimal RIOT program, including the structure of the Makefile and how to run it under Linux.

## [Part 3: Shell und Commands](Tutorials/Chapter_1_Basics/03_ShellCommands_de.md) (:de: only)

Part 3 provides a first insight on how to write interactive RIOT programs using the shell. Here we will write a simple command handler and start the shell.

---

# [Chapter 2: Crypto](Tutorials/Chapter_2_Crypto)

Chapter 2 provides the necessary knowledge how to write RIOT programs that use cryptographic algorithms. We will cover the algorithms  AES-ECB, AES-CBC and RSA.

## [Part 4: AES in Electronic Codebook (ECB) mode](Tutorials/Chapter_2_Crypto/04_AES_ECB_en.md)

Here we will demonstrate the basics of using AES in ECB mode under RIOT.

## [Part 5: AES in Cipher Block Chaining (CBC) mode](Tutorials/Chapter_2_Crypto/05_AES_CBC_en.md)

The previous program will be extended such that data can be encrypted in Cipher Block Chaining mode.

## [Excursion: Transferring AES-CBC encrypted data over the network](Tutorials/Chapter_2_Crypto/06_UDP_de.md) (:de: only)

No new crypto algorithm will be introduced here, but rather we will use the known AES-CBC algorithm to exchange secret messages between client and server.

## [Part 6: RSA encryption using RELIC tookit](Tutorials/Chapter_2_Crypto/07_Relic_de.md) (:de: only)

In this part we show how to encrypt data using the RSA implementation of the RELIC toolkit.

---

# [Chapter 3: benchmarking and results](Tutorials/Chapter_3_Results/08_Benchmarking_de.md) (:de: only)

In this short chapter we present the results of simple benchmark algorithms. 