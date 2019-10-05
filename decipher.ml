open State

let decipher_AES input key =
  let st = init_state input key true in

  inv_add_round_key st;

  let max_rounds = ref 0 in

  if String.length key = 32 then max_rounds := 10
  else if String.length key = 48 then max_rounds := 12
  else if String.length key = 64 then max_rounds := 14
  else failwith "Invalid key length";

  for round = !max_rounds-1 downto 1 do
    inv_shift_rows st;
    inv_sub_bytes st;
    inv_add_round_key st;
    inv_mix_cols st;
  done;

  inv_shift_rows st;
  inv_sub_bytes st;
  inv_add_round_key st;

  get_data st
