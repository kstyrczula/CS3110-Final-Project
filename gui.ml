open GMain
open GdkKeysyms
open Cipher
open Decipher
open Scanf
open State

(* #####################################################################
 * Converting strings to hex and vice versa *)


(* [explode str] turns string [str] into a array of characters,
 * with the characters appearing in the same order as in [str] *)
let explode str =
  let rec expl_helper s idx acc =
    if idx = String.length s then acc
    else expl_helper s (idx + 1) (acc.(idx) <- s.[idx]; acc) in
  expl_helper str 0 (Array.make (String.length str) ' ')

(* [explode_rev_lst str] turns string [str] into a list of characters,
 * with the characters appearing in the reverse order *)
let explode_rev_lst str =
  let rec erl_helper s acc =
    let len = String.length s in
    if len = 0 then acc
    else erl_helper (Str.last_chars s (len - 1)) ((s.[0])::acc) in
  erl_helper str []

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
  (String.make 1 (int_to_hex_ch (n/16))) ^
  (String.make 1 (int_to_hex_ch (n mod 16)))

(* [string_to_hex str] tranlates string [str] into hexadecimal *)
let string_to_hex str =
  let rec sth_helper lst acc =
    match lst with
    | [] -> acc
    | h::t -> sth_helper t ((int_to_hex (Char.code h))^acc) in
  sth_helper (explode_rev_lst (Scanf.unescaped str)) ""

(* [hex_ch_to_int] takes a character and converts it from hexadecimal
 * to an integer
 * raises: Failure "Undefined" if character not in [0-9] [a-f] *)
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

(* [hex_byte_to_int byte] takes string [byte] and translates from hexadecimal
 * to an integer
 * requires: [byte] must have length 2 and contain only chars [0-9][a-f] *)
let hex_byte_to_int byte =
  let chars = explode byte in
  16 * (hex_ch_to_int chars.(0)) + (hex_ch_to_int chars.(1))

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

(* [hex_to_string hex] takes hexadecimal string [hex] and translates it into
 * a string using ASCII codes
 * require: [hex] must contain only chars [0-9] and [a-f] and must have
 * even length *)
let hex_to_string hex =
  let rec hts_helper arr idx acc =
    if idx = Array.length arr then acc
    else
      let str_ch = Char.escaped (Char.chr (hex_byte_to_int arr.(idx))) in
      hts_helper arr (idx + 1) (acc^str_ch) in
  hts_helper (string_to_bytes hex) 0 ""

(* [i_xor] is the inverse of add_round_key when going back a step *)
let i_xor state =
  let rkeys = state.keys in
  for mat = 0 to Array.length state.data - 1 do
    for col = 0 to Array.length state.data.(mat) - 1 do
      for row = 0 to Array.length state.data.(mat).(col) - 1 do
        state.data.(mat).(col).(row) <-
    state.data.(mat).(col).(row) lxor rkeys.((state.round - 1)* 4 + row).(col)
      done
    done
  done;
  state.round <- state.round - 1

(* [xor] is the inverse of inv_add_round_key when gong forward a step *)
let xor state =
    let rkeys = state.keys in
    for mat = 0 to Array.length state.data - 1 do
      for col = 0 to Array.length state.data.(mat) - 1 do
        for row = 0 to Array.length state.data.(mat).(col) - 1 do
            state.data.(mat).(col).(row) <-
 state.data.(mat).(col).(row) lxor rkeys.((state.round - 1) * 4 + 3 - row).(col)
          done
        done
      done;
    state.round <- state.round - 1

(* ##################################################################### *)


let locale = GtkMain.Main.init ()

(* [run inverse key input out ()] runs either a cipher or inverse cipher
 * on [input] and [key] depending on the state of [inverse] and puts the
 * output in [out] *)
let run inverse key input out () =
  let is_inv = inverse#active in
  let s = string_to_hex input#text in
  let k = key#text in
  if not is_inv
  then begin
    let output = hex_to_string (cipher_AES s k) in
    out#set_text output
  end
  else
    let output = hex_to_string (decipher_AES s k) in
    out#set_text output

(* [key_gen box text ()] takes the input string in [box] and generates a
 * random hexadecimal key of an appropriate length *)
let key_gen box text () =
  let opt = box#entry#text in
  let size =
    if opt = "128" then 32
    else if opt = "192" then 48
    else 64
  in
  let rec str_gen len acc =
    if len = 0 then acc
    else str_gen (len-1) (acc^(Char.escaped (int_to_hex_ch (Random.int 16))))
  in
  let new_key = str_gen size "" in
  text#set_text new_key

(* [cleanup] resets the gui to the default *)
let cleanup inverse key box input output stp op stp_state () =
  inverse#set_active false;
  key#set_text "Enter key here";
  box#entry#set_text "...or choose number of bits in random key (default 256)";
  input#set_text "Enter data to encrypt here";
  output#set_text "Output will appear here";
  stp#set_text "Step output";
  op#set_text "Previous operation";
  stp_state := None

(* [toggle checkbutton f ()] calls [f] based on the status of [checkbutton] *)
let toggle checkbutton f () = f checkbutton#active

(*############################################################################*)
(* step functions *)

(*abstract type representing the state when stepping through AES*)
type step_state =
  { forward_state : state;
    backward_state : state;
    mutable cur_step : int
  }

(*[init_step_state] initializes the step_state *)
let init_step_state step_state input key =
  try step_state := Some
    { forward_state = (init_state (string_to_hex input#text) (key#text) false);
        backward_state = (init_state (string_to_hex input#text) key#text true);
      cur_step = 0;
    }; !step_state
  with e -> failwith((Printexc.to_string e))

(* [initialize_step] initializes the GEntrys for stepping*)
let initialize_step sp_state out op () =
  try match (sp_state ()) with
  | Some a ->
  out#set_text (hex_to_string (get_data a.forward_state));
  op#set_text "Initialized data"
  | None -> ()
  with e -> failwith((Printexc.to_string e))

(* [step_forward] steps the step state forward and display the step output *)
let step_forward stp_state out op box () =
  match !stp_state with
  | None -> ()
  | Some stp_st ->
    let opt = box#entry#text in
    let size =
      if opt = "128" then 40
      else if opt = "192" then 48
      else 56 in
    if stp_st.cur_step >= size then (op#set_text "Finished encrypting") else
    if stp_st.cur_step >= 0 then begin
      let op_name =
        if stp_st.cur_step = 0 then "add_round_key"
        else if stp_st.cur_step = (size - 1) then "add_round_key"
        else match (stp_st.cur_step - 1) mod 4 with
          | 0 -> "sub_bytes"
          | 1 -> "shift_rows"
          | 2 -> "mix_cols"
          | 3 -> "add_round_key"
      in
      match op_name with
      | "sub_bytes" -> begin
          sub_bytes stp_st.forward_state;
          out#set_text (hex_to_string (get_data stp_st.forward_state));
          op#set_text "sub_bytes";
          stp_st.cur_step <- stp_st.cur_step + 1
      end
      | "shift_rows" -> begin
          shift_rows stp_st.forward_state;
          out#set_text (hex_to_string (get_data stp_st.forward_state));
          op#set_text "shift_rows";
          stp_st.cur_step <- stp_st.cur_step + 1
        end
      | "mix_cols" -> begin
          mix_cols stp_st.forward_state;
          out#set_text (hex_to_string (get_data stp_st.forward_state));
          op#set_text "mix_cols";
          stp_st.cur_step <- stp_st.cur_step + 1
        end
      | "add_round_key" -> begin
          add_round_key stp_st.forward_state;
          out#set_text (hex_to_string (get_data stp_st.forward_state));
          op#set_text "add_round_key";
          stp_st.cur_step <- stp_st.cur_step + 1
        end
    end else begin
      (* for stepping forward after stepping backwards *)
      let op_name =
        if stp_st.cur_step = (-1) then "i_xor"
               else if stp_st.cur_step = (-size) then "i_xor"
               else match (-stp_st.cur_step - 1) mod 4 with
                 | 2 -> "inv_sub_bytes"
                 | 1 -> "inv_shift_rows"
                 | 0 -> "inv_mix_cols"
                 | 3 -> "i_xor"
      in
      match op_name with
      | "inv_sub_bytes" -> begin
          sub_bytes stp_st.backward_state;
          out#set_text (hex_to_string (get_data stp_st.backward_state));
          op#set_text "inv_shift_rows";
          stp_st.cur_step <- stp_st.cur_step + 1
        end
      | "inv_shift_rows" -> begin
          shift_rows stp_st.backward_state;
          out#set_text (hex_to_string (get_data stp_st.backward_state));
          op#set_text (if stp_st.cur_step = (-2)
                       then "inv_add_round_key" else "inv_mix_cols");
          stp_st.cur_step <- stp_st.cur_step + 1
        end
      | "inv_mix_cols" -> begin
          mix_cols stp_st.backward_state;
          out#set_text (hex_to_string (get_data stp_st.backward_state));
          op#set_text "inv_add_round_key";
          stp_st.cur_step <- stp_st.cur_step + 1
        end
      | "i_xor" -> begin
          xor stp_st.backward_state;
          out#set_text (hex_to_string (get_data stp_st.backward_state));
          op#set_text (if stp_st.cur_step = (-1)
                       then "Initialized data" else "inv_sub_bytes");
          stp_st.cur_step <- stp_st.cur_step + 1
        end
    end

(* [step_backward] steps the state backwards and displays the step*)
let step_backward stp_state out op box () =
  match !stp_state with
  | None -> ()
  | Some step ->
      let opt = box#entry#text in
      let size =
        if opt = "128" then -40
        else if opt = "192" then -48
        else -56 in
      if step.cur_step <= size then op#set_text "Finished decrypting" else
      if step.cur_step <= 0 then begin
        let op_name =
        if step.cur_step = 0 then "inv_add_round_key"
        else if step.cur_step = (size + 1) then "inv_add_round_key"
        else match (-step.cur_step - 1) mod 4 with
          | 0 -> "inv_shift_rows"
          | 1 -> "inv_sub_bytes"
          | 2 -> "inv_add_round_key"
          | 3 -> "inv_mix_cols"
      in
      match op_name with
      | "inv_sub_bytes" -> begin
          inv_sub_bytes step.backward_state;
          out#set_text (hex_to_string (get_data step.backward_state));
          op#set_text "inv_sub_bytes";
          step.cur_step <- step.cur_step - 1
        end
      | "inv_shift_rows" -> begin
          inv_shift_rows step.backward_state;
          out#set_text (hex_to_string (get_data step.backward_state));
          op#set_text "inv_shift_rows";
          step.cur_step <- step.cur_step - 1
        end
      | "inv_mix_cols" -> begin
          inv_mix_cols step.backward_state;
          out#set_text (hex_to_string (get_data step.backward_state));
          op#set_text "inv_mix_cols";
          step.cur_step <- step.cur_step - 1
        end
      | "inv_add_round_key" -> begin
          inv_add_round_key step.backward_state;
          out#set_text (hex_to_string (get_data step.backward_state));
          op#set_text "inv_add_round_key";
          step.cur_step <- step.cur_step - 1
        end
    end else begin
        (* for stepping back after having gone in the forward *)
        let op_name =
          if step.cur_step = (1) then "xor"
          else if step.cur_step = (-size) then "xor"
          else match (step.cur_step - 1) mod 4 with
            | 2 -> "shift_rows"
            | 1 -> "sub_bytes"
            | 0 -> "xor"
            | 3 -> "mix_cols"
        in
        match op_name with
        | "sub_bytes" -> begin
            inv_sub_bytes step.forward_state;
            out#set_text (hex_to_string (get_data step.forward_state));
            op#set_text "add_round_key";
            step.cur_step <- step.cur_step - 1
          end
        | "shift_rows" -> begin
            inv_shift_rows step.forward_state;
            out#set_text (hex_to_string (get_data step.forward_state));
            op#set_text "sub_bytes";
            step.cur_step <- step.cur_step - 1
          end
        | "mix_cols" -> begin
            inv_mix_cols step.forward_state;
            out#set_text (hex_to_string (get_data step.forward_state));
            op#set_text "shift_rows";
            step.cur_step <- step.cur_step - 1
          end
        | "xor" -> begin
            i_xor step.forward_state;
            out#set_text (hex_to_string (get_data step.forward_state));
            op#set_text (if step.cur_step = (1)
                         then "Initialized data"
                         else if step.cur_step = (-size)
                         then "shift_rows"
                         else "mix_cols");
            step.cur_step <- step.cur_step - 1
          end
end

let main () =
  let stp_state = ref None in
  let window = GWindow.window ~width:1280 ~height:720
      ~title:"AES Encryption" () in
  let vbox = GPack.vbox ~packing:window#add () in
  window#connect#destroy ~callback:Main.quit;

  (* Menu bar *)
  let menubar = GMenu.menu_bar ~packing:vbox#pack () in
  let factory = new GMenu.factory menubar in
  let accel_group = factory#accel_group in
  let file_menu = factory#add_submenu "File" in

  (* File menu *)
  let factory = new GMenu.factory file_menu ~accel_group in
  factory#add_item "Quit" ~key:_Q ~callback: Main.quit;

  (* Text boxes for key and data *)
  let inverse = GButton.check_button ~label:"Inverse?"
      ~active:false
      ~packing:vbox#add () in
  let key = GEdit.entry ~text:"Enter key here"
      ~max_length:64
      ~visibility:true
      ~packing:vbox#add () in
  (*Drop-down / combo box for key gen options *)
  let combobox = GEdit.combo ~popdown_strings: ["128";"192";"256"]
      ~enable_arrow_keys: true
      ~packing:vbox#add () in
  let execute = GButton.button ~label:"Generate key"
      ~packing:(vbox#pack ~expand: false ~fill: true ~padding:10) () in
  let input = GEdit.entry ~text:"Enter data to encrypt here"
      ~packing:vbox#add () in
  let output = GEdit.entry ~text:"Output will appear here"
      ~editable:false
      ~packing:vbox#add () in
  let go = GButton.button ~stock:`OK
      ~packing:(vbox#pack ~padding:10)  () in
  let reset = GButton.button ~label:"Reset"
      ~packing:(vbox#pack ~expand: true ~fill: false ~padding:10) () in

  (* Row of step buttons *)
  let frame = GBin.frame ~label: "Step options" ~packing:vbox#add () in
  let bbox = GPack.button_box `HORIZONTAL ~packing:frame#add () in
  let step_output = GEdit.entry ~text:"Step output" ~editable:false
      ~packing:bbox#add () in
  let op_box = GEdit.entry ~text:"Previous operation" ~editable:false
      ~packing:bbox#add () in
  let init_step = GButton.button ~label:"Start step-through"
      ~packing:bbox#add () in
  let f_step = GButton.button ~label:"Step forward" ~packing:bbox#add () in
  let b_step = GButton.button ~label:"Step backward" ~packing:bbox#add () in

  (* button callbacks *)
  go#connect#clicked ~callback:(run inverse key input output);
  input#select_region ~start:0 ~stop:input#text_length;
  combobox#entry#set_text
    "...or choose number of bits in random key (default 256)";
  combobox#entry#set_editable false;
  execute#connect#clicked ~callback:(key_gen combobox key);
  reset#connect#clicked
    ~callback:(cleanup inverse key combobox input output step_output op_box stp_state);

  init_step#connect#clicked ~callback:(initialize_step
    (fun () -> (init_step_state stp_state input key )) step_output op_box);
  f_step#connect#clicked
    ~callback:(step_forward (stp_state) step_output op_box combobox);
  b_step#connect#clicked
    ~callback:(step_backward (stp_state) step_output op_box combobox);

(*combobox#entry#connect#activate ~callback: (key_gen combobox key);*)

  let hbox = GPack.hbox ~packing:vbox#add () in
  let check = GButton.check_button ~label:"Editable"
      ~active:true
      ~packing:hbox#add () in
  check#connect#toggled ~callback:(toggle check input#set_editable);

  let check2 = GButton.check_button ~label:"Visible"
      ~active:true
      ~packing:hbox#add () in
  check2#connect#toggled ~callback:(toggle check2 input#set_visibility);

  (* Display the windows and enter Gtk+ main loop *)

  window#add_accel_group accel_group;
  window#show ();
  Main.main ()

(* comment out to test conversions *)
let () = main ()
