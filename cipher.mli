(* [cipher_AES] returns the cipher text of the hexadecimal input string and key
 * using the AES encryption algorythm, uses functions from State
 * requires:
 *   - data and key strings must only contain characters in [0-9][a-f]
 *   - data string must have even length
 *   - key string must have length 32, 48, or 64 *)
val cipher_AES : string -> string -> string
