# HCEMobileTicketing
### Providing Security for Mobile Ticketing applications backed by TrustZone

Mobile devices are ubiquitous and are a central part of everyday's life. This ubiquity led Public Transport Operators to start thinking of ticketing solutions that could take advantage of the capabilities of such devices, aligned with the growth in popularity and standardization of the Near Field Communication technology. 

However, mobile ticketing solutions are prone to be exploited if there is a malicious agent that is able to compromise the operating system. While there are always-online approaches, it is interesting to develop a solution that allows for cards to be secured locally on the device, with their transactions to be done without the risk of exploitation even in the presence of a compromised OS. This thesis then aims to deliver such solution by leveraging the benefits of ARM TrustZone for the storage of cards and execution of the critical transactions of mobile ticketing applications, protected from the rich OS that can't be trusted. 

We propose DBStore, an SQL-based management system for sensitive data backed by ARM TrustZone. Through its small Trusted Computing Base and the isolation guaranteed by the TrustZone technology, we argue that this solution provides good security guarantees, making it applicable to real-world scenarios. This repo proposes a prototype developed according to a real-world application, to be named as _HCE Mobile Ticketing_. We show how DBStore could be integrated by an application that requires secure management of data and operations over it.

## *Roadmap*

1. Finish Initialization protocol:
   - [x] Adapt the algorithm in the thesis to OP-TEE
   - [x] Cryptographic algorithms all being applied correctly
   - [x] Code cleanup
   - [x] Better memory management (mallocs, frees)
   - [ ] Detect and treat error codes
   - [x] Protection against replay attacks
2. Finish Invocation protocol
   - [x] Adapt the algorithm in the thesis to OP-TEE
   - [x] Cryptographic algorithms all being applied correctly
   - [x] Code cleanup
   - [x] Better memory management (mallocs, frees)
   - [ ] Detect and treat error codes
   - [x] Protection against replay attacks
3. Get SQL up and running (using LittleD library)
   - [x] Adapt LittleD to use the Global Platform's API for IO, as well as adding missing libc functions
   - [x] Get LittleD to compile and run on the emulator
   - [x] Run the example on LittleD's github
   - [x] Manage to run the queries from the paper (or at least an adaptation)
4. Port the prototype to the Nitrogen board
   - [ ] Compile OP-TEE using the instructions provided by Nuno Duarte
   - [ ] Configuring Android to be able to run on the board
   - [ ] Get Android and OP-TEE running on the board
   - [ ] Get the prototype running on the board

## *The Program*

DBStore runs on [OP-TEE](https://github.com/OP-TEE/optee_os), with the program being divided in two components: the Trusted Application (TA), which resides in the Secure World (SW), and the Normal Application (NA), which runs on the guest OS, aka Normal World (NW). The TA is loaded when the Secure World OS boots. As such, only the NA needs to be executed by the user. This repo contains a demo, where the NA functions as the ticketing server and terminal. This simplifies things and is enough for a proof-of-concept.

By executing the DBStore demo NA (./DBStore), the user gets prompted with a command pannel:

> Welcome to DBStore! <br>
Write "init" to start initialization protocol (sending o) <br>
Write "inv" to start invocation protocol (sending o o o and session_key <br>
Write "exit" to quit the program <br>

#### _init_
Initializes both NA and TA, i.e., mutually authentication and agreement on the session key to be used. Messages are exchanged by both worlds using shared memory and all communications NA>TA are encrypted using asymmetric encryption (NA encrypts the data using DBStore's TA Public Key (PK) and sends its own Public Key (PK) to the TA). TA generates a Session Key (SK), and the responses to NA are encrypted symmetrically using this SK, which is encrypted assymetrically using DBStore NA's PK. A counter is also started, to guarantee message freshness, and is also exchanged between worlds.

#### _inv_
An inv command is followed by an SQL statement, which DBStore will run using [LittleD](https://github.com/graemedouglas/LittleD). Messages are exchanged by both worlds using shared memory and all communications NA<>TA are encrypted using symmetric encryption (via the SK). HMACs are also sent alongside messages, to authenticate them and guarantee their integrity. The counter is still used to guarantee message freshness.

#### _exit_
Quits DBStore NA.


Cryptographic algorithms used in the NW are provided by [Openssl](https://www.openssl.org/), while in the SW [Libtomcrypt](https://github.com/libtom/libtomcrypt) is used. Additionally, the I/O and crypto's API is the one specified in [GlobalPlatform's Internal API v1.2](https://www.globalplatform.org/specificationsdevice.asp).
It is also important to mention that LittleD was adapted to run on the SW. The library itself is quite limited (for instance, doesn't support UPDATEs or DELETEs of rows) and was programmed for a 32bit system. As such, some "hammering" was required to be able to use it on a 64bit system and using the GlobalPlatform's Internal API v1.2. This adaption of LittleD provided on this repo made the library even more limited, as only the SELECT * syntax is supported and the WHERE syntax required adding a parser. However, given that porting an SQL library was a part of this work and not the focus, it is enough to show the feasibility of DBStore as a solution.

## *Example*

This is a small example of a interaction between DBStore NA and TA:

```
./DBStore
init                                               //Estabilishes a session
inv CREATE TABLE t (i INT, s STRING(10));          //Creates a table t with two columns
inv INSERT INTO t VALUES (1, 'One');               //Inserts a row into t
inv INSERT INTO t VALUES (2, 'Simple');
inv INSERT INTO t VALUES (3, 'Test');
inv SELECT * FROM t WHERE i=3;                     //Grabs the last row of t
inv DELETE t;                                      //Deletes t
exit                                               //Exits DBStore NA
