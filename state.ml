(* AF :
 * [state.data] represents an ASCII string with characters translated to integers.
 * The matrices in [state.data] are column major, so the string "abcdefghijklmnop"
 * is encoded like so:
     | 97  101 105 109 |
     | 98  102 106 110 |
     | 99  103 107 111 |
     | 100 104 108 112 |
   Strings of length > 16 are encoded using multiple matrices.
   Strings whose lengths are not multiples of 16 are padded with spaces.
    - The empty string is not padded (as 0 is a multiple of 16.
   Note that our use of ASCII codes means that strings of different case will
   cipher differently.
   [state.keys] and [state.round] are invisible to the end user *)
(* RI :
 * All matrices in [state.data] must be 4x4 and all entries integers in [0-255].
 * All arrays in [state.keys] must be length 4 with integer entries in [0-255]
 * [state.round] is a positive integer *)
type state = { mutable data : (int array array) array;
               mutable keys : int array array;
               mutable round : int}

(* [s_box] is a 2D array representing the substitution transformation *)
let s_box =
  [| [|99; 124; 119; 123; 242; 107; 111; 197; 48; 1; 103; 43; 254; 215; 171; 118|];
     [|202; 130; 201; 125; 250; 89; 71; 240; 173; 212; 162; 175; 156; 164; 114; 192|];
     [|183; 253; 147; 38; 54; 63; 247; 204; 52; 165; 229; 241; 113; 216; 49; 21|];
     [|4; 199; 35; 195; 24; 150; 5; 154; 7; 18; 128; 226; 235; 39; 178; 117|];
     [|9; 131; 44; 26; 27; 110; 90; 160; 82; 59; 214; 179; 41; 227; 47; 132|];
     [|83; 209; 0; 237; 32; 252; 177; 91; 106; 203; 190; 57; 74; 76; 88; 207|];
     [|208; 239; 170; 251; 67; 77; 51; 133; 69; 249; 2; 127; 80; 60; 159; 168|];
     [|81; 163; 64; 143; 146; 157; 56; 245; 188; 182; 218; 33; 16; 255; 243; 210|];
     [|205; 12; 19; 236; 95; 151; 68; 23; 196; 167; 126; 61; 100; 93; 25; 115|];
     [|96; 129; 79; 220; 34; 42; 144; 136; 70; 238; 184; 20; 222; 94; 11; 219|];
     [|224; 50; 58; 10; 73; 6; 36; 92; 194; 211; 172; 98; 145; 149; 228; 121|];
     [|231; 200; 55; 109; 141; 213; 78; 169; 108; 86; 244; 234; 101; 122; 174; 8|];
     [|186; 120; 37; 46; 28; 166; 180; 198; 232; 221; 116; 31; 75; 189; 139; 138|];
     [|112; 62; 181; 102; 72; 3; 246; 14; 97; 53; 87; 185; 134; 193; 29; 158|];
     [|225; 248; 152; 17; 105; 217; 142; 148; 155; 30; 135; 233; 206; 85; 40; 223|];
     [|140; 161; 137; 13; 191; 230; 66; 104; 65; 153; 45; 15; 176; 84; 187; 22|] |]

(* [rcon] is the round constant array used in key expansion *)
let rcon =
  [| [|1; 0; 0; 0|];
     [|2; 0; 0; 0|];
     [|4; 0; 0; 0|];
     [|8; 0; 0; 0|];
     [|16; 0; 0; 0|];
     [|32; 0; 0; 0|];
     [|64; 0; 0; 0|];
     [|128; 0; 0; 0|];
     [|27; 0; 0; 0|];
     [|54; 0; 0; 0|] |]

(* [find_TwoD x mat] looks for [x] in matrix [mat] and returns the row and
 * column as a tuple.
 * raises: Failure "Not_found" if [x] is not in [mat] *)
let find_TwoD x mat =
  let num_rows = Array.length mat in
  if num_rows = 0 then failwith "Not_found"
  else
    let num_cols = Array.length mat.(0) in
    let out_ref = ref (-1, -1) in
    for i = 0 to num_rows - 1 do
      for j = 0 to num_cols - 1 do
        if mat.(i).(j) = x then out_ref := (i, j)
        else ();
      done
    done;
    if !out_ref = (-1, -1) then failwith ((string_of_int x) ^ "Not_found")
    else !out_ref

(* [explode_rev_lst str] turns string [str] into a list of characters,
 * with the characters appearing in the reverse order *)
let explode_rev_lst str =
  let rec erl_helper s acc =
    let len = String.length s in
    if len = 0 then acc
    else erl_helper (Str.last_chars s (len - 1)) ((s.[0])::acc) in
  erl_helper str []

(* [hex_ch_to_int] takes a character and converts it from hexadecimal
 * to an integer
 * raises: Failure "Undefined" if character not in [0-9][a-f] *)
let hex_ch_to_int = function
  | '0' -> 0
  | '1' -> 1
  | '2' -> 2
  | '3' -> 3
  | '4' -> 4
  | '5' -> 5
  | '6' -> 6
  | '7' -> 7
  | '8' -> 8
  | '9' -> 9
  | 'a' -> 10
  | 'b' -> 11
  | 'c' -> 12
  | 'd' -> 13
  | 'e' -> 14
  | 'f' -> 15
  | _ -> failwith "Undefined"

(* [hex_to_int] takes a string and translates it from hexadecimal
 * to an integer
 * requires: the string must contain only chars [0-9] and [a-f] *)
let hex_to_int str =
  let rec hti_helper lst n acc =
    match lst with
    | [] -> acc
    | h::t ->
      let ch_val = hex_ch_to_int h in
      hti_helper t (n +. 1.0) (ch_val * (truncate (16.0**n)) + acc) in
  let char_list = explode_rev_lst str in
  hti_helper char_list 0.0 0

(* [int_to_hex_ch] takes an integer from 0 to 15 and converts it to hexadecimal
 * raises: Failure "Undefined" if integer not in [0-15] *)
let int_to_hex_ch = function
  | 0 -> '0'
  | 1 -> '1'
  | 2 -> '2'
  | 3 -> '3'
  | 4 -> '4'
  | 5 -> '5'
  | 6 -> '6'
  | 7 -> '7'
  | 8 -> '8'
  | 9 -> '9'
  | 10 -> 'a'
  | 11 -> 'b'
  | 12 -> 'c'
  | 13 -> 'd'
  | 14 -> 'e'
  | 15 -> 'f'
  | _ -> failwith "Undefined"

(* [int_to_hex num] takes an integer [n] and translates it into hexadecimal
 * requires: [n] is in [0-255]*)
let int_to_hex n =
  (String.make 1 (int_to_hex_ch (n/16))) ^ (String.make 1 (int_to_hex_ch (n mod 16)))

(* [string_to_hex str] tranlates string [str] into hexadecimal *)
let string_to_hex str =
  let rec sth_helper lst acc =
    match lst with
    | [] -> acc
    | h::t -> sth_helper t ((int_to_hex (Char.code h))^acc) in
  sth_helper (explode_rev_lst str) ""

(* splits a string [str] of [0-9][a-f] characters into an array of
 * string representations of hexadecimal values of bytes
 * requires: the length of [str] must be even *)
let string_to_bytes str =
  let rec stb_helper s arr idx =
    if String.length s = 0 then arr
    else
      let s1 = Str.first_chars s 2 in
      let s2 = Str.last_chars s (String.length s - 2) in
      stb_helper s2 (arr.(idx) <- s1; arr) (idx + 1) in
  let result = Array.make ((String.length str)/2) "" in
  stb_helper str result 0

(* splits a string [str] of [0-9][a-f] characters into an array of
 * string representations of hexadecimal values of 32-bit words
 * requires: the length of [str] must be a multiple of 8 *)
let string_to_words str =
  let rec stw_helper s arr idx =
    if String.length s = 0 then arr
    else
      let s1 = Str.first_chars s 8 in
      let s2 = Str.last_chars s (String.length s - 8) in
      stw_helper s2 (arr.(idx) <- s1; arr) (idx + 1) in
  let result = Array.make ((String.length str)/8) "" in
  stw_helper str result 0

(* [pad str] concatenates the hex equivalent of empty strings to hex string
 * [str] until it has a multiple of 32
 * requires: [str] must have even length *)
let rec pad str =
  if (String.length str) mod 32 = 0 then str
  else pad (str^"20")

(* [init_data input] initializes the data structure with the values
 * corresponding to hex string [input]
 * requires: [input] must have even length with characters in [0-9][a-f]*)
let init_data input =
  if input = "" then [||]
  else
    let bytes = string_to_bytes input in
    let len = Array.length bytes in
    let num_mats = truncate (ceil (float (len) /. 16.0)) in
    let data_mats = Array.make num_mats (Array.make_matrix 4 4 0) in
    for m = 0 to num_mats - 1 do
      data_mats.(m) <- Array.make_matrix 4 4 0;
      for j = 0 to 3 do
        for i = 0 to 3 do
          data_mats.(m).(i).(j) <- hex_to_int bytes.(16*m + 4*j + i);
        done
      done
    done; data_mats

(* [sub_word word] performs a substitution on each byte of 32-bit word [word],
 * where [word] is an int array with 4 separated bytes
 * returns: the updated [word]
 * requires: [word] has length 4 and each element is in range [0-255]*)
let sub_word word =
  for i = 0 to 3 do
    let old = word.(i) in
    let row = old / 16 in
    let col = old mod 16 in
    let new_val = s_box.(row).(col) in
    word.(i) <- new_val;
  done; word

(* [rot_word word] performs a cyclic permutation on int_array [word]
 * returns: the updated [word]
 * requires: [word] has length 4 *)
let rot_word word =
  let temp = word.(0) in
  word.(0) <- word.(1);
  word.(1) <- word.(2);
  word.(2) <- word.(3);
  word.(3) <- temp;
  word

(* [xor_w] performs the bitwise xor operation on words [w1] and [w2] where
 * [w1] and [w2] are arrays of ints representing bytes
 * requires: [w1] and [w2] are the same length *)
let xor_w w1 w2 =
  let out_ref = ref (Array.make (Array.length w1) 0) in
  for i = 0 to Array.length w1 - 1 do
    !out_ref.(i) <- w1.(i) lxor w2.(i);
  done; !out_ref

(* [key_expand] implements key expansion given a list [fkb] of the integer
 * representations of the bytes of the originally inputted key along with
 * the number of rounds of encryption [num_rounds] and number of 32-bit words
 * [nk] n the initial key *)
let key_expand fkb num_rounds nk =
  let keys = Array.make (4*(num_rounds + 1)) [|0; 0; 0; 0|] in
  for i = 0 to nk - 1 do
    keys.(i) <- [|fkb.(4*i); fkb.(4*i + 1); fkb.(4*i + 2); fkb.(4*i + 3)|];
  done;
  let temp = ref (Array.make 4 0) in
  for i = nk to 4*(num_rounds + 1) - 1 do
    temp := Array.copy keys.(i - 1);
    if i mod nk = 0
    then temp := xor_w (sub_word (rot_word !temp)) rcon.(i/nk - 1)
    else if nk > 6 && i mod nk = 4
    then temp := sub_word !temp
    else ();
    keys.(i) <- xor_w keys.(i - nk) !temp;
  done; keys

(* [init_keys] initializes the keys array accordingly based on the
 * input string [key]
 * requires: [key] must only contain characters from [0-9] and [a-f]
 * raises: Failure "Invalid key length" if [key] has wrong length *)
let init_keys key =
  (* AES-128, 32 characters in hex representation of 128 bits, 10 rounds *)
  if String.length key = 32
  then let fkb = Array.map hex_to_int (string_to_bytes key) in
    key_expand fkb 10 4
    (* AES-192, 48 characters in hex representation of 192 bits, 12 rounds *)
  else if String.length key = 48
  then let fkb = Array.map hex_to_int (string_to_bytes key) in
    key_expand fkb 12 6
    (* AES-256, 64 characters in hex representation of 256 bits, 14 rounds *)
  else if String.length key = 64
  then let fkb = Array.map hex_to_int (string_to_bytes key) in
    key_expand fkb 14 8
  else failwith "Invalid key length"

(* [rev_keys] returns a new array that is [arr] in reverse order *)
let rev_keys arr =
  let len = Array.length arr in
  let new_arr = Array.make len (Array.make 0 0) in
  for i = 0 to len - 1 do
      new_arr.(i) <- arr.(len - 1 - i);
  done; new_arr

let init_state input key is_inv =
  { data = init_data (pad input);
    keys = if is_inv then rev_keys (init_keys key) else init_keys key;
    round = 0}

let get_data state =
  let num_mats = Array.length state.data in
  let out_ref = ref "" in
  for m = 0 to num_mats - 1 do
    for j = 0 to 3 do
      for i = 0 to 3 do
        out_ref := !out_ref ^ (int_to_hex state.data.(m).(i).(j));
      done
    done
  done; !out_ref

let sub_bytes state =
  let num_mats = Array.length state.data in
  for m = 0 to num_mats - 1 do
    for j = 0 to 3 do
      for i = 0 to 3 do
        let old = state.data.(m).(i).(j) in
        let row = old / 16 in
        let col = old mod 16 in
        let new_val = s_box.(row).(col) in
        state.data.(m).(i).(j) <- new_val;
      done
    done
  done; ()

let inv_sub_bytes state =
  let num_mats = Array.length state.data in
  for m = 0 to num_mats - 1 do
    for j = 0 to 3 do
      for i = 0 to 3 do
        let old = state.data.(m).(i).(j) in
        match find_TwoD old s_box with
        | (row, col) ->
          let new_val = 16*row + col in
          state.data.(m).(i).(j) <- new_val;
      done
    done
  done; ()

let shift_rows state =
  let num_mats = Array.length state.data in
  let new_mat_arr = Array.make num_mats (Array.make_matrix 4 4 0) in
  for m = 0 to num_mats - 1 do
    let new_mat = Array.make_matrix 4 4 0 in
    new_mat_arr.(m) <- new_mat
  done;
  for m = 0 to num_mats - 1 do
    for i = 0 to 3 do
      for j = 0 to 3 do
        new_mat_arr.(m).(i).(j) <- state.data.(m).(i).(j)
      done
    done
  done;
  for m = 0 to num_mats - 1 do
    for i = 0 to 3 do
      for j = 0 to 3 do
        state.data.(m).(i).(j) <- (new_mat_arr).(m).(i).(((i + j) mod 4))
      done
    done
  done

let inv_shift_rows state =
  let num_mats = Array.length state.data in
  let new_mat_arr = Array.make num_mats (Array.make_matrix 4 4 0) in
  for m = 0 to num_mats - 1 do
    let new_mat = Array.make_matrix 4 4 0 in
    new_mat_arr.(m) <- new_mat
  done;
  for m = 0 to num_mats - 1 do
    for i = 0 to 3 do
      for j = 0 to 3 do
        new_mat_arr.(m).(i).(j) <- state.data.(m).(i).(j)
      done
    done
  done;
  for m = 0 to num_mats - 1 do
    for i = 0 to 3 do
      for j = 0 to 3 do
        state.data.(m).(i).((i+j) mod 4) <- (new_mat_arr).(m).(i).(j)
      done
    done
  done

(* adds enough zeros to make string b have a length of 8 chars *)
let rec addzeros b =
  if String.length b < 8 then (String.make (8 - String.length b) '0') ^ b
  else b

(* takes two binary strings of length 8 or less and multiplies to produce
 * binary encoded in an array of length 15 with index 0 representing the
 * 2^14 place *)
let multiply b1 b2 =
  let b1_arr = Array.make 8 0 in
  let b2_arr = Array.make 8 0 in
  let prod_arr = Array.make 8 0 in
  let prod_arr_arr = Array.make 8 prod_arr in
  let sum_arr = Array.make 15 0 in
  let b1 = addzeros b1 in
  let b2 = addzeros b2 in
  for i= 0 to 7 do
    prod_arr_arr.(i) <- Array.make 8 0
  done;
  (*b1_arr and b2_arr are the int arrays of bits *)
  for i = 0 to 7 do
    b1_arr.(i) <- (Char.code(String.get b1 i) - 48)
  done;
  for i = 0 to 7 do
    b2_arr.(i) <- (Char.code(String.get b2 i) - 48)
  done;
  for i = 7 downto 0 do
    for j = 7 downto 0 do
      prod_arr_arr.(i).(j) <- (b1_arr.(i) * b2_arr.(j));
    done
  done;
  let sum_helper praa sum_ind n=
    let acc = ref 0 in
    let m = sum_ind - n in
    let n' = ref n in
    let m' = ref m in
    while !n'>=m && !m'<=n do
      acc := !acc + praa.(!n').(!m');
      n' := !n'-1;
      m' := !m'+1;
    done; (!acc mod 2)
  in
  for s = 14 downto 7 do
    sum_arr.(s) <- sum_helper prod_arr_arr s 7
  done;
  for s = 6 downto 0 do
    sum_arr.(s) <- sum_helper prod_arr_arr s s
  done;
  sum_arr


(* if the 8th place or higher has a 1, returns the highest such place *)
let mod_helper prod =
  let temp = ref None in
  for i=0 to 6 do
    if prod.(i) = 1 then
      if !temp = None then temp := Some i
      else ()
    else ()
  done;
  !temp

(* [bin_arr_to_dec arr] takes the length 15 array [arr] of 0's and 1's and
 * converts it into a decimal integer
 * requires: [arr] is a list of length 14 *)
let bin_arr_to_dec arr =
  let sum = ref 0 in
  for i = 0 to 14 do
    sum := arr.(i) * (truncate (2. ** (float (14 - i)))) + !sum;
  done; !sum

(* performs the redefined modulo by [x^8 + x^4 + x^3 + x + 1] *)
let modular (prod: int array) =
  let temp = ref (mod_helper prod) in
  let shift = ref 0 in
  while !temp <> None do
    match !temp with
    |None -> (failwith "Impossible")
    |Some i -> shift := (14 - i) - 8 ;
      if (prod.(14- (8+ (!shift)))=0) then prod.(14-(8+(!shift))) <- 1
      else prod.(14- (8+ (!shift))) <- 0;
      if (prod.(14- (4+ (!shift)))=0) then prod.(14-(4+(!shift))) <- 1
      else prod.(14- (4+ (!shift))) <- 0;
      if (prod.(14- (3+ (!shift)))=0) then prod.(14-(3+(!shift))) <- 1
      else prod.(14- (3+ (!shift))) <- 0;
      if (prod.(14- (1+ (!shift)))=0) then prod.(14-(1+(!shift))) <- 1
      else prod.(14- (1+ (!shift))) <- 0;
      if (prod.(14-(!shift))=0) then prod.(14-(0+(!shift))) <- 1
      else prod.(14-(!shift)) <- 0;
      temp := mod_helper prod;
  done; bin_arr_to_dec prod

(* converts decimal to binary string *)
let bin_of_decimal d =
  let onesorzeros d = if d = 1 then "1" else "0" in
  let rec bd_helper d acc =
    if d = 0 then acc
    else bd_helper (d/2) (onesorzeros (d mod 2)^acc) in
  bd_helper d ""

let mix_cols state =
  let num_mats = Array.length state.data in
  let new_mat_arr = Array.make num_mats (Array.make_matrix 4 4 0) in
  for m = 0 to num_mats - 1 do
    let new_mat = Array.make_matrix 4 4 0 in
    new_mat_arr.(m) <- new_mat
  done;
  for m = 0 to num_mats - 1 do
    for i = 0 to 3 do
      for j = 0 to 3 do
        new_mat_arr.(m).(i).(j) <- state.data.(m).(i).(j)
      done
    done
  done;
  for m = 0 to num_mats-1 do
    for col = 0 to 3 do
      state.data.(m).(0).(col) <-
        (new_mat_arr.(m).(0).(col) |> bin_of_decimal |> multiply "10" |> modular) lxor
        (new_mat_arr.(m).(1).(col) |> bin_of_decimal |> multiply "11" |> modular) lxor
        (new_mat_arr.(m).(2).(col) |> bin_of_decimal |> multiply "1" |> modular) lxor
        (new_mat_arr.(m).(3).(col) |> bin_of_decimal |> multiply "1" |> modular);
      state.data.(m).(1).(col) <-
        (new_mat_arr.(m).(0).(col) |> bin_of_decimal |> multiply "1" |> modular) lxor
        (new_mat_arr.(m).(1).(col) |> bin_of_decimal |> multiply "10" |> modular) lxor
        (new_mat_arr.(m).(2).(col) |> bin_of_decimal |> multiply "11" |> modular) lxor
        (new_mat_arr.(m).(3).(col) |> bin_of_decimal |> multiply "1" |> modular);
      state.data.(m).(2).(col) <-
        (new_mat_arr.(m).(0).(col) |> bin_of_decimal |> multiply "1" |> modular) lxor
        (new_mat_arr.(m).(1).(col) |> bin_of_decimal |> multiply "1" |> modular) lxor
        (new_mat_arr.(m).(2).(col) |> bin_of_decimal |> multiply "10" |> modular) lxor
        (new_mat_arr.(m).(3).(col) |> bin_of_decimal |> multiply "11" |> modular);
      state.data.(m).(3).(col) <-
        (new_mat_arr.(m).(0).(col) |> bin_of_decimal |> multiply "11" |> modular) lxor
        (new_mat_arr.(m).(1).(col) |> bin_of_decimal |> multiply "1" |> modular) lxor
        (new_mat_arr.(m).(2).(col) |> bin_of_decimal |> multiply "1" |> modular) lxor
        (new_mat_arr.(m).(3).(col) |> bin_of_decimal |> multiply "10" |> modular);
    done
  done

let inv_mix_cols state=
  let num_mats = Array.length state.data in
  let new_mat_arr = Array.make num_mats (Array.make_matrix 4 4 0) in
  for m = 0 to num_mats - 1 do
    let new_mat = Array.make_matrix 4 4 0 in
    new_mat_arr.(m) <- new_mat
  done;
  for m = 0 to num_mats - 1 do
    for i = 0 to 3 do
      for j = 0 to 3 do
        new_mat_arr.(m).(i).(j) <- state.data.(m).(i).(j)
      done
    done
  done;
  for m = 0 to num_mats-1 do
    for col = 0 to 3 do
      state.data.(m).(0).(col) <-
        (new_mat_arr.(m).(0).(col) |> bin_of_decimal |> multiply "1110" |> modular) lxor
        (new_mat_arr.(m).(1).(col) |> bin_of_decimal |> multiply "1011" |> modular) lxor
        (new_mat_arr.(m).(2).(col) |> bin_of_decimal |> multiply "1101" |> modular) lxor
        (new_mat_arr.(m).(3).(col) |> bin_of_decimal |> multiply "1001" |> modular);
      state.data.(m).(1).(col) <-
        (new_mat_arr.(m).(0).(col) |> bin_of_decimal |> multiply "1001" |> modular) lxor
        (new_mat_arr.(m).(1).(col) |> bin_of_decimal |> multiply "1110" |> modular) lxor
        (new_mat_arr.(m).(2).(col) |> bin_of_decimal |> multiply "1011" |> modular) lxor
        (new_mat_arr.(m).(3).(col) |> bin_of_decimal |> multiply "1101" |> modular);
      state.data.(m).(2).(col) <-
        (new_mat_arr.(m).(0).(col) |> bin_of_decimal |> multiply "1101" |> modular) lxor
        (new_mat_arr.(m).(1).(col) |> bin_of_decimal |> multiply "1001" |> modular) lxor
        (new_mat_arr.(m).(2).(col) |> bin_of_decimal |> multiply "1110" |> modular) lxor
        (new_mat_arr.(m).(3).(col) |> bin_of_decimal |> multiply "1011" |> modular);
      state.data.(m).(3).(col) <-
        (new_mat_arr.(m).(0).(col) |> bin_of_decimal |> multiply "1011" |> modular) lxor
        (new_mat_arr.(m).(1).(col) |> bin_of_decimal |> multiply "1101" |> modular) lxor
        (new_mat_arr.(m).(2).(col) |> bin_of_decimal |> multiply "1001" |> modular) lxor
        (new_mat_arr.(m).(3).(col) |> bin_of_decimal |> multiply "1110" |> modular);
    done
  done

let add_round_key state =
  let rkeys = state.keys in
  for mat = 0 to Array.length state.data - 1 do
    for col = 0 to Array.length state.data.(mat) - 1 do
      for row = 0 to Array.length state.data.(mat).(col) - 1 do
        state.data.(mat).(col).(row) <-
          state.data.(mat).(col).(row) lxor rkeys.(state.round * 4 + row).(col)
      done
    done
  done;
  state.round <- state.round + 1

let inv_add_round_key state =
  let rkeys = state.keys in
  for mat = 0 to Array.length state.data - 1 do
    for col = 0 to Array.length state.data.(mat) - 1 do
      for row = 0 to Array.length state.data.(mat).(col) - 1 do
          state.data.(mat).(col).(row) <-
            state.data.(mat).(col).(row) lxor rkeys.(state.round * 4 + 3 - row).(col)
        done
      done
    done;
    state.round <- state.round + 1
