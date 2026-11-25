# Introduction

A Safe can batch several calls into a single transaction for its owners to review, sign, and execute. [Safe Wallet's Transaction Builder](https://help.safe.global/articles/4180673514-transaction-builder) provides a visual editor for these batches.

Brownie Safe lets you build the batch from Python. Run your calls as the Safe account on a local fork, collect their Brownie receipts, and turn them into one MultiSend transaction. Preview the batch through the Safe contract before proposing it to the hosted [Safe Queue Service](https://docs.safe.global/core-api/safe-queue-service-overview).
