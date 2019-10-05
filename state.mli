(* [state] is an abstract data structure representing the data and keys
 * throughout the encryption process *)
type state

(* [init_state] initializes state data structure based on inputted hexadecimal
 * data string and key string and boolean flag to indicate whether the state is
 * used for a forward or inverse cipher
 * requires:
 *   - data and key strings must only contain characters in [0-9][a-f]
 *   - data string must have even length
 *   - key string must have length 32, 48, or 64 *)
val init_state : string -> string -> bool -> state

(* [get_data] returns the current data in the state encoded as a string *)
val get_data : state -> string

(* [sub_bytes] is the SubBytes() function for the cipher *)
val sub_bytes : state -> unit

(* [shift_rows] is the ShiftRows() function for the cipher *)
val shift_rows : state -> unit

(* [mix_cols] is the MixColumns() function for the cipher *)
val mix_cols : state -> unit

(* [add_round_key] is the AddRoundKey() function for the cipher *)
val add_round_key : state -> unit

(* [inv_add_round_key] is the inverse of AddRoundKey() function for the cipher *)
val inv_add_round_key : state -> unit

(* [inv_shift_rows] is the InvShiftRows() function for the inverse cipher *)
val inv_shift_rows : state -> unit

(* [inv_sub_bytes] is the InvSubBytes() function for the inverse cipher *)
val inv_sub_bytes : state -> unit

(* [inv_mix_cols] is the InvMixColumns() function for the inverse cipher *)
val inv_mix_cols : state -> unit
