# HCEMobileTicketing
### Providing Security for Mobile Ticketing applications backed by TrustZone

## *Roadmap*

1. Finish Initialization protocol:
   - [x] Adapt the algorithm in the thesis to OP-TEE
   - [x] Encryption algorithms all being applied correctly
   - [x] Code cleanup
   - [x] Better memory management (mallocs, frees)
   - [ ] Detect and treat error codes
   - [ ] Protection against replay attacks
2. Finish Invocation protocol
   - [x] HMAC sent alongside message
   - [x] Cryptography implemented
   - [ ] Protection against replay attacks
3. Get SQLite up and running
