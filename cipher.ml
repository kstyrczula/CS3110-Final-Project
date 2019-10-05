open State

let cipher_AES input key =
  let st = init_state input key false in

  add_round_key st;

  let max_rounds = ref 0 in

  if String.length key = 32 then max_rounds := 10
  else if String.length key = 48 then max_rounds := 12
  else if String.length key = 64 then max_rounds := 14
  else failwith "Invalid key length";

  for round = 1 to !max_rounds-1 do
    sub_bytes st;
    shift_rows st;
    mix_cols st;
    add_round_key st;
  done;

  sub_bytes st;
  shift_rows st;
  add_round_key st;

  get_data st