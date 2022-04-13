Introduction
============

Since multisig signers are usually slow to fulfill their duties, it's common to batch multiple actions and send them as one transaction.
Batching also serves as a rudimentary zap if you are not concerned about the exactly matching in/out values and allow for some slippage.

Gnosis Safe has an excellent Transaction Builder app that allows scaffolding complex interactions.
This approach is usually faster and cheaper than deploying a bespoke contract for every transaction. 

Ape Safe expands on this idea. It allows you to use multisig as a regular account and then convert the transaction history into one multisend transaction and make sure it works before it hits the signers.
