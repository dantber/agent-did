/**
 * Base58 encoding/decoding (Bitcoin alphabet)
 * Used for did:key encoding
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = 58;

/**
 * Encode a Uint8Array to base58 string
 */
export function encode(data: Uint8Array): string {
  if (data.length === 0) return '';

  // Count leading zeros
  let zeros = 0;
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    zeros++;
  }

  // Convert to base58
  const digits: number[] = [];
  let carry: number;

  for (let i = 0; i < data.length; i++) {
    carry = data[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % BASE;
      carry = (carry / BASE) | 0;
    }
    while (carry > 0) {
      digits.push(carry % BASE);
      carry = (carry / BASE) | 0;
    }
  }

  // Add leading zeros
  let result = '1'.repeat(zeros);

  // Add digits in reverse order
  for (let i = digits.length - 1; i >= 0; i--) {
    result += ALPHABET[digits[i]];
  }

  return result;
}

/**
 * Decode a base58 string to Uint8Array
 */
export function decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Count leading '1's (which represent zeros)
  let zeros = 0;
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    zeros++;
  }

  // Convert from base58
  const digits: number[] = [];
  let carry: number;

  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const value = ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    carry = value;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] * BASE;
      digits[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      digits.push(carry & 0xff);
      carry >>= 8;
    }
  }

  // Add leading zeros
  const result = new Uint8Array(zeros + digits.length);
  for (let i = 0; i < zeros; i++) {
    result[i] = 0;
  }
  for (let i = 0; i < digits.length; i++) {
    result[zeros + digits.length - 1 - i] = digits[i];
  }

  return result;
}
