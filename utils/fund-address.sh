#!/bin/bash

# VietChain Fund Address Utility
# Usage: ./fund-address.sh <address> [amount] [denom]

set -e

# Default values
DEFAULT_AMOUNT="1000"
DEFAULT_DENOM="stake"
DEFAULT_FROM="alice"

# Check if address is provided
if [ -z "$1" ]; then
    echo "❌ Error: Address is required"
    echo "Usage: $0 <address> [amount] [denom]"
    echo "Example: $0 vnic19rl4cm2hmr8afy4kldpxz3fka4jguq0a3fccce 5000 stake"
    exit 1
fi

# Get parameters
ADDRESS="$1"
AMOUNT="${2:-$DEFAULT_AMOUNT}"
DENOM="${3:-$DEFAULT_DENOM}"

echo "💰 Funding VietChain Address"
echo "📍 Address: $ADDRESS"
echo "💵 Amount: $AMOUNT$DENOM"
echo "👤 From: $DEFAULT_FROM"
echo ""

# Validate address format
if [[ ! "$ADDRESS" =~ ^vnic[0-9a-z]{39}$ ]]; then
    echo "❌ Error: Invalid VietChain address format"
    echo "Address should start with 'vnic' and be 43 characters long"
    exit 1
fi

# Check if sender key exists
if ! vnicd keys show "$DEFAULT_FROM" &>/dev/null; then
    echo "❌ Error: Sender key '$DEFAULT_FROM' not found"
    echo "Available keys:"
    vnicd keys list
    exit 1
fi

# Check sender balance
echo "🔍 Checking sender balance..."
SENDER_BALANCE=$(vnicd query bank balances $(vnicd keys show $DEFAULT_FROM -a) --output json | jq -r ".balances[] | select(.denom==\"$DENOM\") | .amount")

if [ -z "$SENDER_BALANCE" ] || [ "$SENDER_BALANCE" = "null" ]; then
    echo "❌ Error: Sender has no $DENOM tokens"
    exit 1
fi

if [ "$SENDER_BALANCE" -lt "$AMOUNT" ]; then
    echo "❌ Error: Insufficient balance. Available: $SENDER_BALANCE$DENOM, Required: $AMOUNT$DENOM"
    exit 1
fi

echo "✅ Sender balance: $SENDER_BALANCE$DENOM"

# Send transaction
echo "📤 Sending transaction..."
TX_HASH=$(vnicd tx bank send "$DEFAULT_FROM" "$ADDRESS" "$AMOUNT$DENOM" --yes --output json | jq -r '.txhash')

if [ -z "$TX_HASH" ] || [ "$TX_HASH" = "null" ]; then
    echo "❌ Error: Transaction failed"
    exit 1
fi

echo "✅ Transaction sent successfully!"
echo "📋 Transaction hash: $TX_HASH"

# Wait a moment and check the recipient balance
echo ""
echo "⏳ Waiting for transaction to be processed..."
sleep 3

echo "🔍 Checking recipient balance..."
RECIPIENT_BALANCE=$(vnicd query bank balances "$ADDRESS" --output json | jq -r ".balances[] | select(.denom==\"$DENOM\") | .amount")

if [ -z "$RECIPIENT_BALANCE" ] || [ "$RECIPIENT_BALANCE" = "null" ]; then
    RECIPIENT_BALANCE="0"
fi

echo "✅ Recipient balance: $RECIPIENT_BALANCE$DENOM"
echo "🎉 Funding completed successfully!"