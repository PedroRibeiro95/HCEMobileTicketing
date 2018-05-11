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
   - [ ] Protection against replay attacks
2. Finish Invocation protocol
   - [x] Adapt the algorithm in the thesis to OP-TEE
   - [x] Cryptographic algorithms all being applied correctly
   - [x] Code cleanup
   - [x] Better memory management (mallocs, frees)
   - [ ] Detect and treat error codes
   - [ ] Protection against replay attacks
3. Get SQL up and running (using LittleD library)
   - [x] Adapt LittleD to use the Global Platform's API for IO, as well as adding missing libc functions
   - [x] Get LittleD to compile and run on the emulator
   - [x] Run the example on LittleD's github
   - [ ] Manage to run the queries from the paper (or at least an adaptation)
4. Port the prototype to the Nitrogen board
   - [ ] Compile OP-TEE using the instructions provided by Nuno Duarte
   - [ ] Configuring Android to be able to run on the board
   - [ ] Get Android and OP-TEE running on the board
   - [ ] Get the prototype running on the board
