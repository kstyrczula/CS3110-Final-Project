(* [decipher_AES] returns the plain text of the input ciphered hexadecimal string
 * and input key using the AES encryption algorithm, uses functions from State
 * requires:
 *   - data and key strings must only contain characters in [0-9][a-f]
 *   - data string must have even length
 *   - key string must have length 32, 48, or 64 *)
val decipher_AES : string -> string -> string
