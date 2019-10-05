open OUnit2
open State
open Cipher
open Decipher

let zkey = "00000000000000000000000000000000"

let st_empstr = init_state "20" zkey false
let st_iempstr = init_state "20" zkey true

let st_z = init_state "00000000000000000000000000000000" zkey false
let st_iz = init_state "00000000000000000000000000000000" zkey true

let st_f = init_state "ffffffffffffffffffffffffffffffff" zkey false
let st_if = init_state "ffffffffffffffffffffffffffffffff" zkey true

(* Hex representation of "Something ore than 16" *)
let two_mat_s = "536f6d657468696e67206d6f7265207468616e203136"

let st_2mat = init_state two_mat_s zkey false
let st_i2mat = init_state two_mat_s zkey true

let key = "abcdefabcdefabcdefabcdefabcdef12"
let st = init_state "" key false
let st_i = init_state "" key true
let st1 = init_state "abcdef0123456789abcdef0123456789" key false
let st2 = init_state
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" key false

(* AES 192 *)
let init_key192 = "000102030405060708090a0b0c0d0e0f1011121314151617"
let st_192 = init_state "00112233445566778899aabbccddeeff" init_key192 false
let ist_192 = init_state "dda97ca4864cdfe06eaf70a0ec0d7191" init_key192 true

(* AES 128 *)
let init_key128 = "000102030405060708090a0b0c0d0e0f"
let st_128 = init_state "00112233445566778899aabbccddeeff" init_key128 false
let ist_128 = init_state "69c4e0d86a7b0430d8cdb78070b4c55a" init_key128 true

(* AES 256 *)
let init_key256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
let st_256 = init_state "00112233445566778899aabbccddeeff" init_key256 false
let ist_256 = init_state "8ea2b7ca516745bfeafc49904b496089" init_key256 true

(* individual steps *)
let key_ex1 = "000102030405060708090a0b0c0d0e0f"
let st_sub1 = init_state "00102030405060708090a0b0c0d0e0f0" key_ex1 false
let st_shift1 = init_state "63cab7040953d051cd60e0e7ba70e18c" key_ex1 false
let st_mix1 = init_state "6353e08c0960e104cd70b751bacad0e7" key_ex1 false

let key_ex2 = "10111213141516175846f2f95c43f4fe"
let st_sub2 = init_state "4f63760643e0aa85aff8c9d041fa0de4" key_ex2 false
let st_shift2 = init_state "84fb386f1ae1ac977941dd70832dd769" key_ex2 false
let st_mix2 = init_state "84e1dd691a41d76f792d389783fbac70" key_ex2 false

let key_ex3 = "544afef55847f0fa4856e2e95c43f4fe"
let st_sub3 = init_state "cb02818c17d2af9c62aa64428bb25fd7" key_ex3 false
let st_shift3 = init_state "1f770c64f0b579deaaac432c3d37cf0e" key_ex3 false
let st_mix3 = init_state "1fb5430ef0accf64aa370cde3d77792c" key_ex3 false

let key_ex4 = "40f949b31cbabd4d48f043b810b7b342"
let st_sub4 = init_state "f75c7778a327c8ed8cfebfc1a6c37f53" key_ex4 false
let st_shift4 = init_state "684af5bc0acce85564bb0878242ed2ed" key_ex4 false
let st_mix4 = init_state "68cc08ed0abbd2bc642ef555244ae878" key_ex4 false

let key_ex5 = "58e151ab04a2a5557effb5416245080c"
let st_sub5 = init_state "22ffc916a81474416496f19c64ae2532" key_ex5 false
let st_shift5 = init_state "9316dd47c2fa92834390a1de43e43f23" key_ex5 false
let st_mix5 = init_state "93faa123c2903f4743e4dd83431692de" key_ex5 false

let key_ex6 = "2ab54bb43a02f8f662e3a95d66410c08"
let st_sub6 = init_state "80121e0776fd1d8a8d8c31bc965d1fee" key_ex6 false
let st_shift6 = init_state "cdc972c53854a47e5d64c765904cc028" key_ex6 false
let st_mix6 = init_state "cd54c7283864c0c55d4c727e90c9a465" key_ex6 false

let key_ex7 = "f501857297448d7ebdf1c6ca87f33e3c"
let st_sub7 = init_state "671ef1fd4e2a1e03dfdcb1ef3d789b30" key_ex7 false
let st_shift7 = init_state "8572a1542fe5727b9e86c8df27bc1404" key_ex7 false
let st_mix7 = init_state "85e5c8042f8614549ebca17b277272df" key_ex7 false

let key_ex8 = "e510976183519b6934157c9ea351f1e0"
let st_sub8 = init_state "0c0370d00c01e622166b8accd6db3a2c" key_ex8 false
let st_shift8 = init_state "fe7b5170fe7c8e93477f7e4bf6b98071" key_ex8 false
let st_mix8 = init_state "fe7c7e71fe7f807047b95193f67b8e4b" key_ex8 false

let key_ex9 = "1ea0372a995309167c439e77ff12051e"
let st_sub9 = init_state "7255dad30fb80310e00d6c6b40d0527c" key_ex9 false
let st_shift9 = init_state "40fc5766766c7bcae1d7507f09700010" key_ex9 false
let st_mix9 = init_state "406c501076d70066e17057ca09fc7b7f" key_ex9 false

let key_ex10 = "dd7e0e887e2fff68608fc842f9dcc154"
let st_sub10 = init_state "a906b254968af4e9b4bdb2d2f0c44336" key_ex10 false
let st_shift10 = init_state "d36f3720907ebf1e8d7a37b58c1c1a05" key_ex10 false
let st_mix10 = init_state "d37e3705907a1a208d1c371e8c6fbfb5" key_ex10 false

let key_ex11 = "859f5f237a8d5a3dc0c02952beefd63a"
let st_sub11 = init_state "88ec930ef5e7e4b6cc32f4c906d29414" key_ex11 false
let st_shift11 = init_state "c4cedcabe694694e4b23bfdd6fb522fa" key_ex11 false
let st_mix11 = init_state "c494bffae62322ab4bb5dc4e6fce69dd" key_ex11 false

let key_ex12 = "de601e7827bcdf2ca223800fd8aeda32"
let st_sub12 = init_state "afb73eeb1cd1b85162280f27fb20d585" key_ex12 false
let st_shift12 = init_state "79a9b2e99c3e6cd1aa3476cc0fb70397" key_ex12 false

(* inverse AES-128 *)
let ikey_1 = "13111d7fe3944a17f307a78b4d2b30c5"
let st_isub1 = init_state "7a9f102789d5f50b2beffd9f3dca4ea7" ikey_1 true
let st_ishift1 = init_state "7ad5fda789ef4e272bca100b3d9ff59f" ikey_1 true
let st_imix1 = init_state "bd6e7c3df2b5779e0b61216e8b10b689" ikey_1 true

let ikey_2 = "549932d1f08557681093ed9cbe2c974e"
let st_isub2 = init_state "5411f4b56bd9700e96a0902fa1bb9aa1" ikey_2 true
let st_ishift2 = init_state "54d990a16ba09ab596bbf40ea111702f" ikey_2 true
let st_imix2 = init_state "fde3bad205e5d0d73547964ef1fe37f1" ikey_2 true

let ikey_3 = "47438735a41c65b9e016baf4aebf7ad2"
let st_isub3 = init_state "3e175076b61c04678dfc2295f6a8bfc0" ikey_3 true
let st_ishift3 = init_state "3e1c22c0b6fcbf768da85067f6170495" ikey_3 true
let st_imix3 = init_state "d1876c0f79c4300ab45594add66ff41f" ikey_3 true

let ikey_4 = "14f9701ae35fe28c440adf4d4ea9c026"
let st_isub4 = init_state "b415f8016858552e4bb6124c5f998a4c" ikey_4 true
let st_ishift4 = init_state "b458124c68b68a014b99f82e5f15554c" ikey_4 true
let st_imix4 = init_state "c62fe109f75eedc3cc79395d84f9cf5d" ikey_4 true

let ikey_5 = "5e390f7df7a69296a7553dc10aa31f6b"
let st_isub5 = init_state "e847f56514dadde23f77b64fe7f7d490" ikey_5 true
let st_ishift5 = init_state "e8dab6901477d4653ff7f5e2e747dd4f" ikey_5 true
let st_imix5 = init_state "c81677bc9b7ac93b25027992b0261996" ikey_5 true

let ikey_6 = "3caaa3e8a99f9deb50f3af57adf622aa"
let st_isub6 = init_state "36400926f9336d2d9fb59d23c42c3950" ikey_6 true
let st_ishift6 = init_state "36339d50f9b539269f2c092dc4406d23" ikey_6 true
let st_imix6 = init_state "247240236966b3fa6ed2753288425b6c" ikey_6 true

let ikey_7 = "47f7f7bc95353e03f96c32bcfd058dfd"
let st_isub7 = init_state "2dfb02343f6d12dd09337ec75b36e3f0" ikey_7 true
let st_ishift7 = init_state "2d6d7ef03f33e334093602dd5bfb12c7" ikey_7 true
let st_imix7 = init_state "fa636a2825b339c940668a3157244d17" ikey_7 true

let ikey_8 = "b6ff744ed2c2c9bf6c590cbf0469bf41"
let st_isub8 = init_state "3b59cb73fcd90ee05774222dc067fb68" ikey_8 true
let st_ishift8 = init_state "3bd92268fc74fb735767cbe0c0590e2d" ikey_8 true
let st_imix8 = init_state "4915598f55e5d7a0daca94fa1f0a63f7" ikey_8 true

let ikey_9 = "b692cf0b643dbdf1be9bc5006830b3fe"
let st_isub9 = init_state "a761ca9b97be8b45d8ad1a611fc97369" ikey_9 true
let st_ishift9 = init_state "a7be1a6997ad739bd8c9ca451f618b61" ikey_9 true
let st_imix9 = init_state "89d810e8855ace682d1843d8cb128fe4" ikey_9 true

let ikey_10 = "d6aa74fdd2af72fadaa678f1d6ab76fe"
let st_isub10 = init_state "63cab7040953d051cd60e0e7ba70e18c" ikey_10 true
let st_ishift10 = init_state "6353e08c0960e104cd70b751bacad0e7" ikey_10 true

let st_add_round1 = init_state "00112233445566778899aabbccddeeff"
    "000102030405060708090a0b0c0d0e0f" false
let st_add_round2 = init_state "00112233445566778899aabbccddeeff"
    "000102030405060708090a0b0c0d0e0f1011121314151617" false
let st_add_round3 = init_state "00112233445566778899aabbccddeeff"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" false

let tests =
  [
    (* init_state and get_data *)
    "empty" >:: (fun _ -> assert_equal "" (get_data st));
    "sanity" >:: (fun _ -> assert_equal "abcdef0123456789abcdef0123456789" (get_data st1));
    "longer" >:: (fun _ -> assert_equal
                     "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" (get_data st2));

    (* Boundary cases empty state/empty string input *)
    "empty_sub" >:: (fun _ -> assert_equal "" (sub_bytes st; get_data st));
    "empty_isub" >:: (fun _ -> assert_equal "" (inv_sub_bytes st_i; get_data st_i));
    "empty_shift" >:: (fun _ -> assert_equal "" (shift_rows st; get_data st));
    "empty_ishift" >:: (fun _ -> assert_equal "" (inv_shift_rows st_i; get_data st_i));
    "empty_mix" >:: (fun _ -> assert_equal "" (mix_cols st; get_data st));
    "empty_imix" >:: (fun _ -> assert_equal "" (inv_mix_cols st_i; get_data st));
    "empty_add" >:: (fun _ -> assert_equal "" (add_round_key st; get_data st));
    "empty_iadd" >:: (fun _ -> assert_equal "" (inv_add_round_key st_i; get_data st_i));
    "empty_cipher" >:: (fun _ -> assert_equal "" (cipher_AES "" zkey));
    "empty_decipher" >:: (fun _ -> assert_equal "" (decipher_AES "" zkey));

    (* Boundary case- 1 matrix all empty string *)
    "1mat_emp_sub" >:: (fun _ -> assert_equal "20202020202020202020202020202020"
                    (sub_bytes st_empstr; inv_sub_bytes st_empstr; get_data st_empstr));
    "1mat_emp_shift" >:: (fun _ -> assert_equal "20202020202020202020202020202020"
                    (shift_rows st_empstr; inv_shift_rows st_empstr; get_data st_empstr));
    "1mat_emp_mix" >:: (fun _ -> assert_equal "20202020202020202020202020202020"
                    (mix_cols st_empstr; inv_mix_cols st_empstr; get_data st_empstr));
    "1mat_emp_add" >:: (fun _ -> assert_equal "20202020202020202020202020202020"
                    (add_round_key st_empstr; get_data st_empstr));
    "1mat_emp_iadd" >:: (fun _ -> assert_equal "94cf7beb1eb2c23103c971ef4faf38ae"
                    (inv_add_round_key st_iempstr; get_data st_iempstr));
    "1mat_emp_all" >:: (fun _ -> assert_equal "20202020202020202020202020202020"
                    (decipher_AES (cipher_AES "20" zkey) zkey));

    (* Boundary case- 1 matrix all 0's *)
    "1mat_z_sub" >:: (fun _ -> assert_equal "00000000000000000000000000000000"
                    (sub_bytes st_z; inv_sub_bytes st_z; get_data st_z));
    "1mat_z_shift" >:: (fun _ -> assert_equal "00000000000000000000000000000000"
                    (shift_rows st_z; inv_shift_rows st_z; get_data st_z));
    "1mat_z_mix" >:: (fun _ -> assert_equal "00000000000000000000000000000000"
                    (mix_cols st_z; inv_mix_cols st_z; get_data st_z));
    "1mat_z_add" >:: (fun _ -> assert_equal "00000000000000000000000000000000"
                    (add_round_key st_z; get_data st_z));
    "1mat_z_iadd" >:: (fun _ -> assert_equal "b4ef5bcb3e92e21123e951cf6f8f188e"
                    (inv_add_round_key st_iz; get_data st_iz));
    "1mat_z_all" >:: (fun _ -> assert_equal "00000000000000000000000000000000"
                    (decipher_AES (cipher_AES "00000000000000000000000000000000" zkey) zkey));

    (* Boundary case- 1 matrix all 255's *)
    "1mat_f_sub" >:: (fun _ -> assert_equal "ffffffffffffffffffffffffffffffff"
                    (sub_bytes st_f; inv_sub_bytes st_f; get_data st_f));
    "1mat_f_shift" >:: (fun _ -> assert_equal "ffffffffffffffffffffffffffffffff"
                    (shift_rows st_f; inv_shift_rows st_f; get_data st_f));
    "1mat_f_mix" >:: (fun _ -> assert_equal "ffffffffffffffffffffffffffffffff"
                    (mix_cols st_f; inv_mix_cols st_f; get_data st_f));
    "1mat_f_add" >:: (fun _ -> assert_equal "ffffffffffffffffffffffffffffffff"
                    (add_round_key st_f; get_data st_f));
    "1mat_f_iadd" >:: (fun _ -> assert_equal "4b10a434c16d1deedc16ae309070e771"
                    (inv_add_round_key st_if; get_data st_if));
    "1mat_f_all" >:: (fun _ -> assert_equal "ffffffffffffffffffffffffffffffff"
                    (decipher_AES (cipher_AES "ffffffffffffffffffffffffffffffff" zkey) zkey));

    (* Test more than one matrix *)
    "2mat_sub" >:: (fun _ -> assert_equal
      "536f6d657468696e67206d6f7265207468616e20313620202020202020202020"
      (sub_bytes st_2mat; inv_sub_bytes st_2mat; get_data st_2mat));
    "2mat_shift" >:: (fun _ -> assert_equal
      "536f6d657468696e67206d6f7265207468616e20313620202020202020202020"
      (shift_rows st_2mat; inv_shift_rows st_2mat; get_data st_2mat));
    "2mat_mix" >:: (fun _ -> assert_equal
      "536f6d657468696e67206d6f7265207468616e20313620202020202020202020"
      (mix_cols st_2mat; inv_mix_cols st_2mat; get_data st_2mat));
    "2mat_add" >:: (fun _ -> assert_equal
      "536f6d657468696e67206d6f7265207468616e20313620202020202020202020"
      (add_round_key st_2mat; get_data st_2mat));
    "2mat_iadd" >:: (fun _ -> assert_equal
      "e78036ae4afa8b7f44c93ca01dea38fadc8e35eb0fa4c23103c971ef4faf38ae"
      (inv_add_round_key st_i2mat; get_data st_i2mat));
    "2mat_all" >:: (fun _ -> assert_equal
      "536f6d657468696e67206d6f7265207468616e20313620202020202020202020"
      (decipher_AES (cipher_AES "536f6d657468696e67206d6f7265207468616e203136" zkey) zkey));

    (* Begin documented test vectors *)

    (* sub_bytes *)
    "sub1" >:: (fun _ -> assert_equal "63cab7040953d051cd60e0e7ba70e18c"
                   (sub_bytes st_sub1; get_data st_sub1));
    "sub2" >:: (fun _ -> assert_equal "84fb386f1ae1ac977941dd70832dd769"
                   (sub_bytes st_sub2; get_data st_sub2));
    "sub3" >:: (fun _ -> assert_equal "1f770c64f0b579deaaac432c3d37cf0e"
                   (sub_bytes st_sub3; get_data st_sub3));
    "sub4" >:: (fun _ -> assert_equal "684af5bc0acce85564bb0878242ed2ed"
                   (sub_bytes st_sub4; get_data st_sub4));
    "sub5" >:: (fun _ -> assert_equal "9316dd47c2fa92834390a1de43e43f23"
                   (sub_bytes st_sub5; get_data st_sub5));
    "sub6" >:: (fun _ -> assert_equal "cdc972c53854a47e5d64c765904cc028"
                   (sub_bytes st_sub6; get_data st_sub6));
    "sub7" >:: (fun _ -> assert_equal "8572a1542fe5727b9e86c8df27bc1404"
                   (sub_bytes st_sub7; get_data st_sub7));
    "sub8" >:: (fun _ -> assert_equal "fe7b5170fe7c8e93477f7e4bf6b98071"
                   (sub_bytes st_sub8; get_data st_sub8));
    "sub9" >:: (fun _ -> assert_equal "40fc5766766c7bcae1d7507f09700010"
                   (sub_bytes st_sub9; get_data st_sub9));
    "sub10" >:: (fun _ -> assert_equal "d36f3720907ebf1e8d7a37b58c1c1a05"
                    (sub_bytes st_sub10; get_data st_sub10));
    "sub11" >:: (fun _ -> assert_equal "c4cedcabe694694e4b23bfdd6fb522fa"
                    (sub_bytes st_sub11; get_data st_sub11));
    "sub12" >:: (fun _ -> assert_equal "79a9b2e99c3e6cd1aa3476cc0fb70397"
                    (sub_bytes st_sub12; get_data st_sub12));

    (*inv_sub_bytes *)
    "isub1" >:: (fun _ -> assert_equal "bd6e7c3df2b5779e0b61216e8b10b689"
                    (inv_sub_bytes st_isub1; get_data st_isub1));
    "isub2" >:: (fun _ -> assert_equal "fde3bad205e5d0d73547964ef1fe37f1"
                    (inv_sub_bytes st_isub2; get_data st_isub2));
    "isub3" >:: (fun _ -> assert_equal "d1876c0f79c4300ab45594add66ff41f"
                    (inv_sub_bytes st_isub3; get_data st_isub3));
    "isub4" >:: (fun _ -> assert_equal "c62fe109f75eedc3cc79395d84f9cf5d"
                    (inv_sub_bytes st_isub4; get_data st_isub4));
    "isub5" >:: (fun _ -> assert_equal "c81677bc9b7ac93b25027992b0261996"
                    (inv_sub_bytes st_isub5; get_data st_isub5));
    "isub6" >:: (fun _ -> assert_equal "247240236966b3fa6ed2753288425b6c"
                    (inv_sub_bytes st_isub6; get_data st_isub6));
    "isub7" >:: (fun _ -> assert_equal "fa636a2825b339c940668a3157244d17"
                    (inv_sub_bytes st_isub7; get_data st_isub7));
    "isub8" >:: (fun _ -> assert_equal "4915598f55e5d7a0daca94fa1f0a63f7"
                    (inv_sub_bytes st_isub8; get_data st_isub8));
    "isub9" >:: (fun _ -> assert_equal "89d810e8855ace682d1843d8cb128fe4"
                    (inv_sub_bytes st_isub9; get_data st_isub9));
    "isub10" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                     (inv_sub_bytes st_isub10; get_data st_isub10));

    (* shift_rows *)
    "shift1" >:: (fun _ -> assert_equal "6353e08c0960e104cd70b751bacad0e7"
                     (shift_rows (st_shift1); get_data st_shift1));
    "shift2" >:: (fun _ -> assert_equal "84e1dd691a41d76f792d389783fbac70"
                     (shift_rows (st_shift2); get_data st_shift2));
    "shift3" >:: (fun _ -> assert_equal "1fb5430ef0accf64aa370cde3d77792c"
                     (shift_rows (st_shift3); get_data st_shift3));
    "shift4" >:: (fun _ -> assert_equal "68cc08ed0abbd2bc642ef555244ae878"
                     (shift_rows (st_shift4); get_data st_shift4));
    "shift5" >:: (fun _ -> assert_equal "93faa123c2903f4743e4dd83431692de"
                     (shift_rows (st_shift5); get_data st_shift5));
    "shift6" >:: (fun _ -> assert_equal "cd54c7283864c0c55d4c727e90c9a465"
                     (shift_rows (st_shift6); get_data st_shift6));
    "shift7" >:: (fun _ -> assert_equal "85e5c8042f8614549ebca17b277272df"
                     (shift_rows (st_shift7); get_data st_shift7));
    "shift8" >:: (fun _ -> assert_equal "fe7c7e71fe7f807047b95193f67b8e4b"
                     (shift_rows (st_shift8); get_data st_shift8));
    "shift9" >:: (fun _ -> assert_equal "406c501076d70066e17057ca09fc7b7f"
                     (shift_rows (st_shift9); get_data st_shift9));
    "shift10" >:: (fun _ -> assert_equal "d37e3705907a1a208d1c371e8c6fbfb5"
                      (shift_rows (st_shift10); get_data st_shift10));
    "shift11" >:: (fun _ -> assert_equal "c494bffae62322ab4bb5dc4e6fce69dd"
                      (shift_rows (st_shift11); get_data st_shift11));
    "shift12" >:: (fun _ -> assert_equal "793e76979c3403e9aab7b2d10fa96ccc"
                      (shift_rows (st_shift12); get_data st_shift12));

    (* inv_shift_rows *)
    "ishift1" >:: (fun _ -> assert_equal "7a9f102789d5f50b2beffd9f3dca4ea7"
                      (inv_shift_rows (st_ishift1); get_data st_ishift1));
    "ishift2" >:: (fun _ -> assert_equal "5411f4b56bd9700e96a0902fa1bb9aa1"
                      (inv_shift_rows (st_ishift2); get_data st_ishift2));
    "ishift3" >:: (fun _ -> assert_equal "3e175076b61c04678dfc2295f6a8bfc0"
                      (inv_shift_rows (st_ishift3); get_data st_ishift3));
    "ishift4" >:: (fun _ -> assert_equal "b415f8016858552e4bb6124c5f998a4c"
                      (inv_shift_rows (st_ishift4); get_data st_ishift4));
    "ishift5" >:: (fun _ -> assert_equal "e847f56514dadde23f77b64fe7f7d490"
                      (inv_shift_rows (st_ishift5); get_data st_ishift5));
    "ishift6" >:: (fun _ -> assert_equal "36400926f9336d2d9fb59d23c42c3950"
                      (inv_shift_rows (st_ishift6); get_data st_ishift6));
    "ishift7" >:: (fun _ -> assert_equal "2dfb02343f6d12dd09337ec75b36e3f0"
                      (inv_shift_rows (st_ishift7); get_data st_ishift7));
    "ishift8" >:: (fun _ -> assert_equal "3b59cb73fcd90ee05774222dc067fb68"
                      (inv_shift_rows (st_ishift8); get_data st_ishift8));
    "ishift9" >:: (fun _ -> assert_equal "a761ca9b97be8b45d8ad1a611fc97369"
                      (inv_shift_rows (st_ishift9); get_data st_ishift9));
    "ishift10" >:: (fun _ -> assert_equal "63cab7040953d051cd60e0e7ba70e18c"
                       (inv_shift_rows (st_ishift10); get_data st_ishift10));

    (* mix_columns *)
    "mix1" >:: (fun _ -> assert_equal "5f72641557f5bc92f7be3b291db9f91a"
                   (mix_cols (st_mix1); get_data st_mix1));
    "mix2" >:: (fun _ -> assert_equal "9f487f794f955f662afc86abd7f1ab29"
                   (mix_cols (st_mix2); get_data st_mix2));
    "mix3" >:: (fun _ -> assert_equal "b7a53ecbbf9d75a0c40efc79b674cc11"
                   (mix_cols (st_mix3); get_data st_mix3));
    "mix4" >:: (fun _ -> assert_equal "7a1e98bdacb6d1141a6944dd06eb2d3e"
                   (mix_cols (st_mix4); get_data st_mix4));
    "mix5" >:: (fun _ -> assert_equal "aaa755b34cffe57cef6f98e1f01c13e6"
                   (mix_cols (st_mix5); get_data st_mix5));
    "mix6" >:: (fun _ -> assert_equal "921f748fd96e937d622d7725ba8ba50c"
                   (mix_cols (st_mix6); get_data st_mix6));
    "mix7" >:: (fun _ -> assert_equal "e913e7b18f507d4b227ef652758acbcc"
                   (mix_cols (st_mix7); get_data st_mix7));
    "mix8" >:: (fun _ -> assert_equal "6cf5edf996eb0a069c4ef21cbfc25762"
                   (mix_cols (st_mix8); get_data st_mix8));
    "mix9" >:: (fun _ -> assert_equal "7478bcdce8a50b81d4327a9009188262"
                   (mix_cols (st_mix9); get_data st_mix9));
    "mix10" >:: (fun _ -> assert_equal "0d73cc2d8f6abe8b0cf2dd9bb83d422e"
                    (mix_cols (st_mix10); get_data st_mix10));
    "mix11" >:: (fun _ -> assert_equal "71d720933b6d677dc00b8f28238e0fb7"
                    (mix_cols (st_mix11); get_data st_mix11));

    (* inv_mix_columns *)
    "imix1" >:: (fun _ -> assert_equal "4773b91ff72f354361cb018ea1e6cf2c"
                    (inv_mix_cols (st_imix1); get_data st_imix1));
    "imix2" >:: (fun _ -> assert_equal "2d7e86a339d9393ee6570a1101904e16"
                    (inv_mix_cols (st_imix2); get_data st_imix2));
    "imix3" >:: (fun _ -> assert_equal "39daee38f4f1a82aaf432410c36d45b9"
                    (inv_mix_cols (st_imix3); get_data st_imix3));
    "imix4" >:: (fun _ -> assert_equal "9a39bf1d05b20a3a476a0bf79fe51184"
                    (inv_mix_cols (st_imix4); get_data st_imix4));
    "imix5" >:: (fun _ -> assert_equal "18f78d779a93eef4f6742967c47f5ffd"
                    (inv_mix_cols (st_imix5); get_data st_imix5));
    "imix6" >:: (fun _ -> assert_equal "85cf8bf472d124c10348f545329c0053"
                    (inv_mix_cols (st_imix6); get_data st_imix6));
    "imix7" >:: (fun _ -> assert_equal "fc1fc1f91934c98210fbfb8da340eb21"
                    (inv_mix_cols (st_imix7); get_data st_imix7));
    "imix8" >:: (fun _ -> assert_equal "076518f0b52ba2fb7a15c8d93be45e00"
                    (inv_mix_cols (st_imix8); get_data st_imix8));
    "imix9" >:: (fun _ -> assert_equal "ef053f7c8b3d32fd4d2a64ad3c93071a"
                    (inv_mix_cols (st_imix9); get_data st_imix9));

    (* add_round_key *)
    "add1" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                   (add_round_key (st_add_round1); get_data st_add_round1));

    "add1.2" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                     (add_round_key (st_add_round2); get_data st_add_round2));

    "add1.3" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                     (add_round_key (st_add_round3); get_data st_add_round3));

    (* AES 128 step through *)
    "add1-0" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                     (add_round_key st_128; get_data st_128));
    "sub1-1" >:: (fun _ -> assert_equal "63cab7040953d051cd60e0e7ba70e18c"
                     (sub_bytes st_128; get_data st_128));
    "shift1-1" >:: (fun _ -> assert_equal "6353e08c0960e104cd70b751bacad0e7"
                       (shift_rows st_128; get_data st_128));
    "mix1-1" >:: (fun _ -> assert_equal "5f72641557f5bc92f7be3b291db9f91a"
                     (mix_cols st_128; get_data st_128));
    "add1-1" >:: (fun _ -> assert_equal "89d810e8855ace682d1843d8cb128fe4"
                     (add_round_key st_128; get_data st_128));
    "sub1-2" >:: (fun _ -> assert_equal "a761ca9b97be8b45d8ad1a611fc97369"
                     (sub_bytes st_128; get_data st_128));
    "shift1-2" >:: (fun _ -> assert_equal "a7be1a6997ad739bd8c9ca451f618b61"
                       (shift_rows st_128; get_data st_128));
    "mix1-2" >:: (fun _ -> assert_equal "ff87968431d86a51645151fa773ad009"
                     (mix_cols st_128; get_data st_128));
    "add1-2" >:: (fun _ -> assert_equal "4915598f55e5d7a0daca94fa1f0a63f7"
                     (add_round_key st_128; get_data st_128));
    "sub1-3" >:: (fun _ -> assert_equal "3b59cb73fcd90ee05774222dc067fb68"
                     (sub_bytes st_128; get_data st_128));
    "shift1-3" >:: (fun _ -> assert_equal "3bd92268fc74fb735767cbe0c0590e2d"
                       (shift_rows st_128; get_data st_128));
    "mix1-3" >:: (fun _ -> assert_equal "4c9c1e66f771f0762c3f868e534df256"
                     (mix_cols st_128; get_data st_128));
    "add1-3" >:: (fun _ -> assert_equal "fa636a2825b339c940668a3157244d17"
                     (add_round_key st_128; get_data st_128));
    "sub1-4" >:: (fun _ -> assert_equal "2dfb02343f6d12dd09337ec75b36e3f0"
                     (sub_bytes st_128; get_data st_128));
    "shift1-4" >:: (fun _ -> assert_equal "2d6d7ef03f33e334093602dd5bfb12c7"
                       (shift_rows st_128; get_data st_128));
    "mix1-4" >:: (fun _ -> assert_equal "6385b79ffc538df997be478e7547d691"
                     (mix_cols st_128; get_data st_128));
    "add1-4" >:: (fun _ -> assert_equal "247240236966b3fa6ed2753288425b6c"
                     (add_round_key st_128; get_data st_128));
    "sub1-5" >:: (fun _ -> assert_equal "36400926f9336d2d9fb59d23c42c3950"
                     (sub_bytes st_128; get_data st_128));
    "shift1-5" >:: (fun _ -> assert_equal "36339d50f9b539269f2c092dc4406d23"
                       (shift_rows st_128; get_data st_128));
    "mix1-5" >:: (fun _ -> assert_equal "f4bcd45432e554d075f1d6c51dd03b3c"
                     (mix_cols st_128; get_data st_128));
    "add1-5" >:: (fun _ -> assert_equal "c81677bc9b7ac93b25027992b0261996"
                     (add_round_key st_128; get_data st_128));
    "sub1-6" >:: (fun _ -> assert_equal "e847f56514dadde23f77b64fe7f7d490"
                     (sub_bytes st_128; get_data st_128));
    "shift1-6" >:: (fun _ -> assert_equal "e8dab6901477d4653ff7f5e2e747dd4f"
                       (shift_rows st_128; get_data st_128));
    "mix1-6" >:: (fun _ -> assert_equal "9816ee7400f87f556b2c049c8e5ad036"
                     (mix_cols st_128; get_data st_128));
    "add1-6" >:: (fun _ -> assert_equal "c62fe109f75eedc3cc79395d84f9cf5d"
                     (add_round_key st_128; get_data st_128));
    "sub1-7" >:: (fun _ -> assert_equal "b415f8016858552e4bb6124c5f998a4c"
                     (sub_bytes st_128; get_data st_128));
    "shift1-7" >:: (fun _ -> assert_equal "b458124c68b68a014b99f82e5f15554c"
                       (shift_rows st_128; get_data st_128));
    "mix1-7" >:: (fun _ -> assert_equal "c57e1c159a9bd286f05f4be098c63439"
                     (mix_cols st_128; get_data st_128));
    "add1-7" >:: (fun _ -> assert_equal "d1876c0f79c4300ab45594add66ff41f"
                     (add_round_key st_128; get_data st_128));
    "sub1-8" >:: (fun _ -> assert_equal "3e175076b61c04678dfc2295f6a8bfc0"
                     (sub_bytes st_128; get_data st_128));
    "shift1-8" >:: (fun _ -> assert_equal "3e1c22c0b6fcbf768da85067f6170495"
                       (shift_rows st_128; get_data st_128));
    "mix1-8" >:: (fun _ -> assert_equal "baa03de7a1f9b56ed5512cba5f414d23"
                     (mix_cols st_128; get_data st_128));
    "add1-8" >:: (fun _ -> assert_equal "fde3bad205e5d0d73547964ef1fe37f1"
                     (add_round_key st_128; get_data st_128));
    "sub1-9" >:: (fun _ -> assert_equal "5411f4b56bd9700e96a0902fa1bb9aa1"
                     (sub_bytes st_128; get_data st_128));
    "shift1-9" >:: (fun _ -> assert_equal "54d990a16ba09ab596bbf40ea111702f"
                       (shift_rows st_128; get_data st_128));
    "mix1-9" >:: (fun _ -> assert_equal "e9f74eec023020f61bf2ccf2353c21c7"
                     (mix_cols st_128; get_data st_128));
    "add1-9" >:: (fun _ -> assert_equal "bd6e7c3df2b5779e0b61216e8b10b689"
                     (add_round_key st_128; get_data st_128));
    "sub1-10" >:: (fun _ -> assert_equal "7a9f102789d5f50b2beffd9f3dca4ea7"
                      (sub_bytes st_128; get_data st_128));
    "shift1-10" >:: (fun _ -> assert_equal "7ad5fda789ef4e272bca100b3d9ff59f"
                        (shift_rows st_128; get_data st_128));
    "add1-10" >:: (fun _ -> assert_equal "69c4e0d86a7b0430d8cdb78070b4c55a"
                      (add_round_key st_128; get_data st_128));

    (* AES 128 inverse step through *)
    "iadd1-0" >:: (fun _ -> assert_equal "7ad5fda789ef4e272bca100b3d9ff59f"
                      (inv_add_round_key ist_128; get_data ist_128));
    "ishift1-1" >:: (fun _ -> assert_equal "7a9f102789d5f50b2beffd9f3dca4ea7"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-1" >:: (fun _ -> assert_equal "bd6e7c3df2b5779e0b61216e8b10b689"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-1" >:: (fun _ -> assert_equal "e9f74eec023020f61bf2ccf2353c21c7"
                      (inv_add_round_key ist_128; get_data ist_128));
    "imix1-1" >:: (fun _ -> assert_equal "54d990a16ba09ab596bbf40ea111702f"
                      (inv_mix_cols ist_128; get_data ist_128));
    "ishift1-2" >:: (fun _ -> assert_equal "5411f4b56bd9700e96a0902fa1bb9aa1"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-2" >:: (fun _ -> assert_equal "fde3bad205e5d0d73547964ef1fe37f1"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-2" >:: (fun _ -> assert_equal "baa03de7a1f9b56ed5512cba5f414d23"
                      (inv_add_round_key ist_128; get_data ist_128));
    "imix1-2" >:: (fun _ -> assert_equal "3e1c22c0b6fcbf768da85067f6170495"
                      (inv_mix_cols ist_128; get_data ist_128));
    "ishift1-3" >:: (fun _ -> assert_equal "3e175076b61c04678dfc2295f6a8bfc0"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-3" >:: (fun _ -> assert_equal "d1876c0f79c4300ab45594add66ff41f"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-3" >:: (fun _ -> assert_equal "c57e1c159a9bd286f05f4be098c63439"
                      (inv_add_round_key ist_128; get_data ist_128));
    "imix1-3" >:: (fun _ -> assert_equal "b458124c68b68a014b99f82e5f15554c"
                      (inv_mix_cols ist_128; get_data ist_128));
    "ishift1-4" >:: (fun _ -> assert_equal "b415f8016858552e4bb6124c5f998a4c"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-4" >:: (fun _ -> assert_equal "c62fe109f75eedc3cc79395d84f9cf5d"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-4" >:: (fun _ -> assert_equal "9816ee7400f87f556b2c049c8e5ad036"
                      (inv_add_round_key ist_128; get_data ist_128));
    "imix1-4" >:: (fun _ -> assert_equal "e8dab6901477d4653ff7f5e2e747dd4f"
                      (inv_mix_cols ist_128; get_data ist_128));
    "ishift1-5" >:: (fun _ -> assert_equal "e847f56514dadde23f77b64fe7f7d490"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-5" >:: (fun _ -> assert_equal "c81677bc9b7ac93b25027992b0261996"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-5" >:: (fun _ -> assert_equal "f4bcd45432e554d075f1d6c51dd03b3c"
                      (inv_add_round_key ist_128; get_data ist_128));
    "imix1-5" >:: (fun _ -> assert_equal "36339d50f9b539269f2c092dc4406d23"
                      (inv_mix_cols ist_128; get_data ist_128));
    "ishift1-6" >:: (fun _ -> assert_equal "36400926f9336d2d9fb59d23c42c3950"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-6" >:: (fun _ -> assert_equal "247240236966b3fa6ed2753288425b6c"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-6" >:: (fun _ -> assert_equal "6385b79ffc538df997be478e7547d691"
                      (inv_add_round_key ist_128; get_data ist_128));
    "imix1-6" >:: (fun _ -> assert_equal "2d6d7ef03f33e334093602dd5bfb12c7"
                      (inv_mix_cols ist_128; get_data ist_128));
    "ishift1-7" >:: (fun _ -> assert_equal "2dfb02343f6d12dd09337ec75b36e3f0"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-7" >:: (fun _ -> assert_equal "fa636a2825b339c940668a3157244d17"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-7" >:: (fun _ -> assert_equal "4c9c1e66f771f0762c3f868e534df256"
                      (inv_add_round_key ist_128; get_data ist_128));
    "imix1-7" >:: (fun _ -> assert_equal "3bd92268fc74fb735767cbe0c0590e2d"
                      (inv_mix_cols ist_128; get_data ist_128));
    "ishift1-8" >:: (fun _ -> assert_equal "3b59cb73fcd90ee05774222dc067fb68"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-8" >:: (fun _ -> assert_equal "4915598f55e5d7a0daca94fa1f0a63f7"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-8" >:: (fun _ -> assert_equal "ff87968431d86a51645151fa773ad009"
                      (inv_add_round_key ist_128; get_data ist_128));
    "imix1-8" >:: (fun _ -> assert_equal "a7be1a6997ad739bd8c9ca451f618b61"
                      (inv_mix_cols ist_128; get_data ist_128));
    "ishift1-9" >:: (fun _ -> assert_equal "a761ca9b97be8b45d8ad1a611fc97369"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-9" >:: (fun _ -> assert_equal "89d810e8855ace682d1843d8cb128fe4"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-9" >:: (fun _ -> assert_equal "5f72641557f5bc92f7be3b291db9f91a"
                      (inv_add_round_key ist_128; get_data ist_128));
    "imix1-9" >:: (fun _ -> assert_equal "6353e08c0960e104cd70b751bacad0e7"
                      (inv_mix_cols ist_128; get_data ist_128));
    "ishift1-10" >:: (fun _ -> assert_equal "63cab7040953d051cd60e0e7ba70e18c"
                        (inv_shift_rows ist_128; get_data ist_128));
    "isub1-10" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                      (inv_sub_bytes ist_128; get_data ist_128));
    "iadd1-10" >:: (fun _ -> assert_equal "00112233445566778899aabbccddeeff"
                      (inv_add_round_key ist_128; get_data ist_128));

    (* AES 192 step through *)
    "add2-0" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                     (add_round_key st_192; get_data st_192));
    "sub2-1" >:: (fun _ -> assert_equal "63cab7040953d051cd60e0e7ba70e18c"
                     (sub_bytes st_192; get_data st_192));
    "shift2-1" >:: (fun _ -> assert_equal "6353e08c0960e104cd70b751bacad0e7"
                       (shift_rows st_192; get_data st_192));
    "mix2-1" >:: (fun _ -> assert_equal "5f72641557f5bc92f7be3b291db9f91a"
                     (mix_cols st_192; get_data st_192));
    "add2-1" >:: (fun _ -> assert_equal "4f63760643e0aa85aff8c9d041fa0de4"
                     (add_round_key st_192; get_data st_192));
    "sub2-2" >:: (fun _ -> assert_equal "84fb386f1ae1ac977941dd70832dd769"
                     (sub_bytes st_192; get_data st_192));
    "shift2-2" >:: (fun _ -> assert_equal "84e1dd691a41d76f792d389783fbac70"
                       (shift_rows st_192; get_data st_192));
    "mix2-2" >:: (fun _ -> assert_equal "9f487f794f955f662afc86abd7f1ab29"
                     (mix_cols st_192; get_data st_192));
    "add2-2" >:: (fun _ -> assert_equal "cb02818c17d2af9c62aa64428bb25fd7"
                     (add_round_key st_192; get_data st_192));
    "sub2-3" >:: (fun _ -> assert_equal "1f770c64f0b579deaaac432c3d37cf0e"
                     (sub_bytes st_192; get_data st_192));
    "shift2-3" >:: (fun _ -> assert_equal "1fb5430ef0accf64aa370cde3d77792c"
                       (shift_rows st_192; get_data st_192));
    "mix2-3" >:: (fun _ -> assert_equal "b7a53ecbbf9d75a0c40efc79b674cc11"
                     (mix_cols st_192; get_data st_192));
    "add2-3" >:: (fun _ -> assert_equal "f75c7778a327c8ed8cfebfc1a6c37f53"
                     (add_round_key st_192; get_data st_192));
    "sub2-4" >:: (fun _ -> assert_equal "684af5bc0acce85564bb0878242ed2ed"
                     (sub_bytes st_192; get_data st_192));
    "shift2-4" >:: (fun _ -> assert_equal "68cc08ed0abbd2bc642ef555244ae878"
                       (shift_rows st_192; get_data st_192));
    "mix2-4" >:: (fun _ -> assert_equal "7a1e98bdacb6d1141a6944dd06eb2d3e"
                     (mix_cols st_192; get_data st_192));
    "add2-4" >:: (fun _ -> assert_equal "22ffc916a81474416496f19c64ae2532"
                     (add_round_key st_192; get_data st_192));
    "sub2-5" >:: (fun _ -> assert_equal "9316dd47c2fa92834390a1de43e43f23"
                     (sub_bytes st_192; get_data st_192));
    "shift2-5" >:: (fun _ -> assert_equal "93faa123c2903f4743e4dd83431692de"
                       (shift_rows st_192; get_data st_192));
    "mix2-5" >:: (fun _ -> assert_equal "aaa755b34cffe57cef6f98e1f01c13e6"
                     (mix_cols st_192; get_data st_192));
    "add2-5" >:: (fun _ -> assert_equal "80121e0776fd1d8a8d8c31bc965d1fee"
                     (add_round_key st_192; get_data st_192));
    "sub2-6" >:: (fun _ -> assert_equal "cdc972c53854a47e5d64c765904cc028"
                     (sub_bytes st_192; get_data st_192));
    "shift2-6" >:: (fun _ -> assert_equal "cd54c7283864c0c55d4c727e90c9a465"
                       (shift_rows st_192; get_data st_192));
    "mix2-6" >:: (fun _ -> assert_equal "921f748fd96e937d622d7725ba8ba50c"
                     (mix_cols st_192; get_data st_192));
    "add2-6" >:: (fun _ -> assert_equal "671ef1fd4e2a1e03dfdcb1ef3d789b30"
                     (add_round_key st_192; get_data st_192));
    "sub2-7" >:: (fun _ -> assert_equal "8572a1542fe5727b9e86c8df27bc1404"
                     (sub_bytes st_192; get_data st_192));
    "shift2-7" >:: (fun _ -> assert_equal "85e5c8042f8614549ebca17b277272df"
                       (shift_rows st_192; get_data st_192));
    "mix2-7" >:: (fun _ -> assert_equal "e913e7b18f507d4b227ef652758acbcc"
                     (mix_cols st_192; get_data st_192));
    "add2-7" >:: (fun _ -> assert_equal "0c0370d00c01e622166b8accd6db3a2c"
                     (add_round_key st_192; get_data st_192));
    "sub2-8" >:: (fun _ -> assert_equal "fe7b5170fe7c8e93477f7e4bf6b98071"
                     (sub_bytes st_192; get_data st_192));
    "shift2-8" >:: (fun _ -> assert_equal "fe7c7e71fe7f807047b95193f67b8e4b"
                       (shift_rows st_192; get_data st_192));
    "mix2-8" >:: (fun _ -> assert_equal "6cf5edf996eb0a069c4ef21cbfc25762"
                     (mix_cols st_192; get_data st_192));
    "add2-8" >:: (fun _ -> assert_equal "7255dad30fb80310e00d6c6b40d0527c"
                     (add_round_key st_192; get_data st_192));
    "sub2-9" >:: (fun _ -> assert_equal "40fc5766766c7bcae1d7507f09700010"
                     (sub_bytes st_192; get_data st_192));
    "shift2-9" >:: (fun _ -> assert_equal "406c501076d70066e17057ca09fc7b7f"
                       (shift_rows st_192; get_data st_192));
    "mix2-9" >:: (fun _ -> assert_equal "7478bcdce8a50b81d4327a9009188262"
                     (mix_cols st_192; get_data st_192));
    "add2-9" >:: (fun _ -> assert_equal "a906b254968af4e9b4bdb2d2f0c44336"
                     (add_round_key st_192; get_data st_192));
    "sub2-10" >:: (fun _ -> assert_equal "d36f3720907ebf1e8d7a37b58c1c1a05"
                      (sub_bytes st_192; get_data st_192));
    "shift2-10" >:: (fun _ -> assert_equal "d37e3705907a1a208d1c371e8c6fbfb5"
                        (shift_rows st_192; get_data st_192));
    "mix2-10" >:: (fun _ -> assert_equal "0d73cc2d8f6abe8b0cf2dd9bb83d422e"
                      (mix_cols st_192; get_data st_192));
    "add2-10" >:: (fun _ -> assert_equal "88ec930ef5e7e4b6cc32f4c906d29414"
                      (add_round_key st_192; get_data st_192));
    "sub2-11" >:: (fun _ -> assert_equal "c4cedcabe694694e4b23bfdd6fb522fa"
                      (sub_bytes st_192; get_data st_192));
    "shift2-11" >:: (fun _ -> assert_equal "c494bffae62322ab4bb5dc4e6fce69dd"
                        (shift_rows st_192; get_data st_192));
    "mix2-11" >:: (fun _ -> assert_equal "71d720933b6d677dc00b8f28238e0fb7"
                      (mix_cols st_192; get_data st_192));
    "add2-11" >:: (fun _ -> assert_equal "afb73eeb1cd1b85162280f27fb20d585"
                      (add_round_key st_192; get_data st_192));
    "sub2-12" >:: (fun _ -> assert_equal "79a9b2e99c3e6cd1aa3476cc0fb70397"
                      (sub_bytes st_192; get_data st_192));
    "shift2-12" >:: (fun _ -> assert_equal "793e76979c3403e9aab7b2d10fa96ccc"
                        (shift_rows st_192; get_data st_192));
    "add2-12" >:: (fun _ -> assert_equal "dda97ca4864cdfe06eaf70a0ec0d7191"
                      (add_round_key st_192; get_data st_192));

    (* AES 192 inverse step through *)
    "iadd2-0" >:: (fun _ -> assert_equal "793e76979c3403e9aab7b2d10fa96ccc"
                      (inv_add_round_key ist_192; get_data ist_192));
    "ishift2-1" >:: (fun _ -> assert_equal "79a9b2e99c3e6cd1aa3476cc0fb70397"
                        (inv_shift_rows ist_192; get_data ist_192));
    "isub2-1" >:: (fun _ -> assert_equal "afb73eeb1cd1b85162280f27fb20d585"
                      (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-1" >:: (fun _ -> assert_equal "71d720933b6d677dc00b8f28238e0fb7"
                      (inv_add_round_key ist_192; get_data ist_192));
    "imix2-1" >:: (fun _ -> assert_equal "c494bffae62322ab4bb5dc4e6fce69dd"
                      (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-2" >:: (fun _ -> assert_equal "c4cedcabe694694e4b23bfdd6fb522fa"
                        (inv_shift_rows ist_192; get_data ist_192));
    "isub2-2" >:: (fun _ -> assert_equal "88ec930ef5e7e4b6cc32f4c906d29414"
                      (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-2" >:: (fun _ -> assert_equal "0d73cc2d8f6abe8b0cf2dd9bb83d422e"
                      (inv_add_round_key ist_192; get_data ist_192));
    "imix2-2" >:: (fun _ -> assert_equal "d37e3705907a1a208d1c371e8c6fbfb5"
                      (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-3" >:: (fun _ -> assert_equal "d36f3720907ebf1e8d7a37b58c1c1a05"
                        (inv_shift_rows ist_192; get_data ist_192));
    "isub2-3" >:: (fun _ -> assert_equal "a906b254968af4e9b4bdb2d2f0c44336"
                      (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-3" >:: (fun _ -> assert_equal "7478bcdce8a50b81d4327a9009188262"
                      (inv_add_round_key ist_192; get_data ist_192));
    "imix2-3" >:: (fun _ -> assert_equal "406c501076d70066e17057ca09fc7b7f"
                      (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-4" >:: (fun _ -> assert_equal "40fc5766766c7bcae1d7507f09700010"
                        (inv_shift_rows ist_192; get_data ist_192));
    "isub2-4" >:: (fun _ -> assert_equal "7255dad30fb80310e00d6c6b40d0527c"
                      (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-4" >:: (fun _ -> assert_equal "6cf5edf996eb0a069c4ef21cbfc25762"
                      (inv_add_round_key ist_192; get_data ist_192));
    "imix2-4" >:: (fun _ -> assert_equal "fe7c7e71fe7f807047b95193f67b8e4b"
                      (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-5" >:: (fun _ -> assert_equal "fe7b5170fe7c8e93477f7e4bf6b98071"
                        (inv_shift_rows ist_192; get_data ist_192));
    "isub2-5" >:: (fun _ -> assert_equal "0c0370d00c01e622166b8accd6db3a2c"
                      (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-5" >:: (fun _ -> assert_equal "e913e7b18f507d4b227ef652758acbcc"
                      (inv_add_round_key ist_192; get_data ist_192));
    "imix2-5" >:: (fun _ -> assert_equal "85e5c8042f8614549ebca17b277272df"
                      (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-6" >:: (fun _ -> assert_equal "8572a1542fe5727b9e86c8df27bc1404"
                        (inv_shift_rows ist_192; get_data ist_192));
    "isub2-6" >:: (fun _ -> assert_equal "671ef1fd4e2a1e03dfdcb1ef3d789b30"
                      (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-6" >:: (fun _ -> assert_equal "921f748fd96e937d622d7725ba8ba50c"
                      (inv_add_round_key ist_192; get_data ist_192));
    "imix2-6" >:: (fun _ -> assert_equal "cd54c7283864c0c55d4c727e90c9a465"
                      (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-7" >:: (fun _ -> assert_equal "cdc972c53854a47e5d64c765904cc028"
                        (inv_shift_rows ist_192; get_data ist_192));
    "isub2-7" >:: (fun _ -> assert_equal "80121e0776fd1d8a8d8c31bc965d1fee"
                      (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-7" >:: (fun _ -> assert_equal "aaa755b34cffe57cef6f98e1f01c13e6"
                      (inv_add_round_key ist_192; get_data ist_192));
    "imix2-7" >:: (fun _ -> assert_equal "93faa123c2903f4743e4dd83431692de"
                      (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-8" >:: (fun _ -> assert_equal "9316dd47c2fa92834390a1de43e43f23"
                        (inv_shift_rows ist_192; get_data ist_192));
    "isub2-8" >:: (fun _ -> assert_equal "22ffc916a81474416496f19c64ae2532"
                      (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-8" >:: (fun _ -> assert_equal "7a1e98bdacb6d1141a6944dd06eb2d3e"
                      (inv_add_round_key ist_192; get_data ist_192));
    "imix2-8" >:: (fun _ -> assert_equal "68cc08ed0abbd2bc642ef555244ae878"
                      (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-9" >:: (fun _ -> assert_equal "684af5bc0acce85564bb0878242ed2ed"
                        (inv_shift_rows ist_192; get_data ist_192));
    "isub2-9" >:: (fun _ -> assert_equal "f75c7778a327c8ed8cfebfc1a6c37f53"
                      (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-9" >:: (fun _ -> assert_equal "b7a53ecbbf9d75a0c40efc79b674cc11"
                      (inv_add_round_key ist_192; get_data ist_192));
    "imix2-9" >:: (fun _ -> assert_equal "1fb5430ef0accf64aa370cde3d77792c"
                      (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-10" >:: (fun _ -> assert_equal "1f770c64f0b579deaaac432c3d37cf0e"
                         (inv_shift_rows ist_192; get_data ist_192));
    "isub2-10" >:: (fun _ -> assert_equal "cb02818c17d2af9c62aa64428bb25fd7"
                       (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-10" >:: (fun _ -> assert_equal "9f487f794f955f662afc86abd7f1ab29"
                       (inv_add_round_key ist_192; get_data ist_192));
    "imix2-10" >:: (fun _ -> assert_equal "84e1dd691a41d76f792d389783fbac70"
                       (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-11" >:: (fun _ -> assert_equal "84fb386f1ae1ac977941dd70832dd769"
                         (inv_shift_rows ist_192; get_data ist_192));
    "isub2-11" >:: (fun _ -> assert_equal "4f63760643e0aa85aff8c9d041fa0de4"
                       (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-11" >:: (fun _ -> assert_equal "5f72641557f5bc92f7be3b291db9f91a"
                       (inv_add_round_key ist_192; get_data ist_192));
    "imix2-11" >:: (fun _ -> assert_equal "6353e08c0960e104cd70b751bacad0e7"
                       (inv_mix_cols ist_192; get_data ist_192));
    "ishift2-12" >:: (fun _ -> assert_equal "63cab7040953d051cd60e0e7ba70e18c"
                         (inv_shift_rows ist_192; get_data ist_192));
    "isub2-12" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                       (inv_sub_bytes ist_192; get_data ist_192));
    "iadd2-12" >:: (fun _ -> assert_equal "00112233445566778899aabbccddeeff"
                       (inv_add_round_key ist_192; get_data ist_192));

    (* AES 256 step through *)
    "add3-0" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                     (add_round_key st_256; get_data st_256));
    "sub3-1" >:: (fun _ -> assert_equal "63cab7040953d051cd60e0e7ba70e18c"
                     (sub_bytes st_256; get_data st_256));
    "shift3-1" >:: (fun _ -> assert_equal "6353e08c0960e104cd70b751bacad0e7"
                       (shift_rows st_256; get_data st_256));
    "mix3-1" >:: (fun _ -> assert_equal "5f72641557f5bc92f7be3b291db9f91a"
                     (mix_cols st_256; get_data st_256));
    "add3-1" >:: (fun _ -> assert_equal "4f63760643e0aa85efa7213201a4e705"
                     (add_round_key st_256; get_data st_256));
    "sub3-2" >:: (fun _ -> assert_equal "84fb386f1ae1ac97df5cfd237c49946b"
                     (sub_bytes st_256; get_data st_256));
    "shift3-2" >:: (fun _ -> assert_equal "84e1fd6b1a5c946fdf4938977cfbac23"
                       (shift_rows st_256; get_data st_256));
    "mix3-2" >:: (fun _ -> assert_equal "bd2a395d2b6ac438d192443e615da195"
                     (mix_cols st_256; get_data st_256));
    "add3-2" >:: (fun _ -> assert_equal "1859fbc28a1c00a078ed8aadc42f6109"
                     (add_round_key st_256; get_data st_256));
    "sub3-3" >:: (fun _ -> assert_equal "adcb0f257e9c63e0bc557e951c15ef01"
                     (sub_bytes st_256; get_data st_256));
    "shift3-3" >:: (fun _ -> assert_equal "ad9c7e017e55ef25bc150fe01ccb6395"
                       (shift_rows st_256; get_data st_256));
    "mix3-3" >:: (fun _ -> assert_equal "810dce0cc9db8172b3678c1e88a1b5bd"
                     (mix_cols st_256; get_data st_256));
    "add3-3" >:: (fun _ -> assert_equal "975c66c1cb9f3fa8a93a28df8ee10f63"
                     (add_round_key st_256; get_data st_256));
    "sub3-4" >:: (fun _ -> assert_equal "884a33781fdb75c2d380349e19f876fb"
                     (sub_bytes st_256; get_data st_256));
    "shift3-4" >:: (fun _ -> assert_equal "88db34fb1f807678d3f833c2194a759e"
                       (shift_rows st_256; get_data st_256));
    "mix3-4" >:: (fun _ -> assert_equal "b2822d81abe6fb275faf103a078c0033"
                     (mix_cols st_256; get_data st_256));
    "add3-4" >:: (fun _ -> assert_equal "1c05f271a417e04ff921c5c104701554"
                     (add_round_key st_256; get_data st_256));
    "sub3-5" >:: (fun _ -> assert_equal "9c6b89a349f0e18499fda678f2515920"
                     (sub_bytes st_256; get_data st_256));
    "shift3-5" >:: (fun _ -> assert_equal "9cf0a62049fd59a399518984f26be178"
                       (shift_rows st_256; get_data st_256));
    "mix3-5" >:: (fun _ -> assert_equal "aeb65ba974e0f822d73f567bdb64c877"
                     (mix_cols st_256; get_data st_256));
    "add3-5" >:: (fun _ -> assert_equal "c357aae11b45b7b0a2c7bd28a8dc99fa"
                     (add_round_key st_256; get_data st_256));
    "sub3-6" >:: (fun _ -> assert_equal "2e5bacf8af6ea9e73ac67a34c286ee2d"
                     (sub_bytes st_256; get_data st_256));
    "shift3-6" >:: (fun _ -> assert_equal "2e6e7a2dafc6eef83a86ace7c25ba934"
                       (shift_rows st_256; get_data st_256));
    "mix3-6" >:: (fun _ -> assert_equal "b951c33c02e9bd29ae25cdb1efa08cc7"
                     (mix_cols st_256; get_data st_256));
    "add3-6" >:: (fun _ -> assert_equal "7f074143cb4e243ec10c815d8375d54c"
                     (add_round_key st_256; get_data st_256));
    "sub3-7" >:: (fun _ -> assert_equal "d2c5831a1f2f36b278fe0c4cec9d0329"
                     (sub_bytes st_256; get_data st_256));
    "shift3-7" >:: (fun _ -> assert_equal "d22f0c291ffe031a789d83b2ecc5364c"
                       (shift_rows st_256; get_data st_256));
    "mix3-7" >:: (fun _ -> assert_equal "ebb19e1c3ee7c9e87d7535e9ed6b9144"
                     (mix_cols st_256; get_data st_256));
    "add3-7" >:: (fun _ -> assert_equal "d653a4696ca0bc0f5acaab5db96c5e7d"
                     (add_round_key st_256; get_data st_256));
    "sub3-8" >:: (fun _ -> assert_equal "f6ed49f950e06576be74624c565058ff"
                     (sub_bytes st_256; get_data st_256));
    "shift3-8" >:: (fun _ -> assert_equal "f6e062ff507458f9be50497656ed654c"
                       (shift_rows st_256; get_data st_256));
    "mix3-8" >:: (fun _ -> assert_equal "5174c8669da98435a8b3e62ca974a5ea"
                     (mix_cols st_256; get_data st_256));
    "add3-8" >:: (fun _ -> assert_equal "5aa858395fd28d7d05e1a38868f3b9c5"
                     (add_round_key st_256; get_data st_256));
    "sub3-9" >:: (fun _ -> assert_equal "bec26a12cfb55dff6bf80ac4450d56a6"
                     (sub_bytes st_256; get_data st_256));
    "shift3-9" >:: (fun _ -> assert_equal "beb50aa6cff856126b0d6aff45c25dc4"
                       (shift_rows st_256; get_data st_256));
    "mix3-9" >:: (fun _ -> assert_equal "0f77ee31d2ccadc05430a83f4ef96ac3"
                     (mix_cols st_256; get_data st_256));
    "add3-9" >:: (fun _ -> assert_equal "4a824851c57e7e47643de50c2af3e8c9"
                     (add_round_key st_256; get_data st_256));
    "sub3-10" >:: (fun _ -> assert_equal "d61352d1a6f3f3a04327d9fee50d9bdd"
                      (sub_bytes st_256; get_data st_256));
    "shift3-10" >:: (fun _ -> assert_equal "d6f3d9dda6279bd1430d52a0e513f3fe"
                        (shift_rows st_256; get_data st_256));
    "mix3-10" >:: (fun _ -> assert_equal "bd86f0ea748fc4f4630f11c1e9331233"
                      (mix_cols st_256; get_data st_256));
    "add3-10" >:: (fun _ -> assert_equal "c14907f6ca3b3aa070e9aa313b52b5ec"
                      (add_round_key st_256; get_data st_256));
    "sub3-11" >:: (fun _ -> assert_equal "783bc54274e280e0511eacc7e200d5ce"
                      (sub_bytes st_256; get_data st_256));
    "shift3-11" >:: (fun _ -> assert_equal "78e2acce741ed5425100c5e0e23b80c7"
                        (shift_rows st_256; get_data st_256));
    "mix3-11" >:: (fun _ -> assert_equal "af8690415d6e1dd387e5fbedd5c89013"
                      (mix_cols st_256; get_data st_256));
    "add3-11" >:: (fun _ -> assert_equal "5f9c6abfbac634aa50409fa766677653"
                      (add_round_key st_256; get_data st_256));
    "sub3-12" >:: (fun _ -> assert_equal "cfde0208f4b418ac5309db5c338538ed"
                      (sub_bytes st_256; get_data st_256));
    "shift3-12" >:: (fun _ -> assert_equal "cfb4dbedf4093808538502ac33de185c"
                        (shift_rows st_256; get_data st_256));
    "mix3-12" >:: (fun _ -> assert_equal "7427fae4d8a695269ce83d315be0392b"
                      (mix_cols st_256; get_data st_256));
    "add3-12" >:: (fun _ -> assert_equal "516604954353950314fb86e401922521"
                      (add_round_key st_256; get_data st_256));
    "sub3-13" >:: (fun _ -> assert_equal "d133f22a1aed2a7bfa0f44697c4f3ffd"
                      (sub_bytes st_256; get_data st_256));
    "shift3-13" >:: (fun _ -> assert_equal "d1ed44fd1a0f3f2afa4ff27b7c332a69"
                        (shift_rows st_256; get_data st_256));
    "mix3-13" >:: (fun _ -> assert_equal "2c21a820306f154ab712c75eee0da04f"
                      (mix_cols st_256; get_data st_256));
    "add3-13" >:: (fun _ -> assert_equal "627bceb9999d5aaac945ecf423f56da5"
                      (add_round_key st_256; get_data st_256));
    "sub3-14" >:: (fun _ -> assert_equal "aa218b56ee5ebeacdd6ecebf26e63c06"
                      (sub_bytes st_256; get_data st_256));
    "shift3-14" >:: (fun _ -> assert_equal "aa5ece06ee6e3c56dde68bac2621bebf"
                        (shift_rows st_256; get_data st_256));
    "add3-14" >:: (fun _ -> assert_equal "8ea2b7ca516745bfeafc49904b496089"
                      (add_round_key st_256; get_data st_256));

    (* AES 256 inverse step through *)
    "iadd3-0" >:: (fun _ -> assert_equal "aa5ece06ee6e3c56dde68bac2621bebf"
                      (inv_add_round_key ist_256; get_data ist_256));
    "ishift3-1" >:: (fun _ -> assert_equal "aa218b56ee5ebeacdd6ecebf26e63c06"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-1" >:: (fun _ -> assert_equal "627bceb9999d5aaac945ecf423f56da5"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-1" >:: (fun _ -> assert_equal "2c21a820306f154ab712c75eee0da04f"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-1" >:: (fun _ -> assert_equal "d1ed44fd1a0f3f2afa4ff27b7c332a69"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-2" >:: (fun _ -> assert_equal "d133f22a1aed2a7bfa0f44697c4f3ffd"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-2" >:: (fun _ -> assert_equal "516604954353950314fb86e401922521"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-2" >:: (fun _ -> assert_equal "7427fae4d8a695269ce83d315be0392b"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-2" >:: (fun _ -> assert_equal "cfb4dbedf4093808538502ac33de185c"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-3" >:: (fun _ -> assert_equal "cfde0208f4b418ac5309db5c338538ed"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-3" >:: (fun _ -> assert_equal "5f9c6abfbac634aa50409fa766677653"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-3" >:: (fun _ -> assert_equal "af8690415d6e1dd387e5fbedd5c89013"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-3" >:: (fun _ -> assert_equal "78e2acce741ed5425100c5e0e23b80c7"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-4" >:: (fun _ -> assert_equal "783bc54274e280e0511eacc7e200d5ce"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-4" >:: (fun _ -> assert_equal "c14907f6ca3b3aa070e9aa313b52b5ec"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-4" >:: (fun _ -> assert_equal "bd86f0ea748fc4f4630f11c1e9331233"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-4" >:: (fun _ -> assert_equal "d6f3d9dda6279bd1430d52a0e513f3fe"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-5" >:: (fun _ -> assert_equal "d61352d1a6f3f3a04327d9fee50d9bdd"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-5" >:: (fun _ -> assert_equal "4a824851c57e7e47643de50c2af3e8c9"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-5" >:: (fun _ -> assert_equal "0f77ee31d2ccadc05430a83f4ef96ac3"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-5" >:: (fun _ -> assert_equal "beb50aa6cff856126b0d6aff45c25dc4"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-6" >:: (fun _ -> assert_equal "bec26a12cfb55dff6bf80ac4450d56a6"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-6" >:: (fun _ -> assert_equal "5aa858395fd28d7d05e1a38868f3b9c5"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-6" >:: (fun _ -> assert_equal "5174c8669da98435a8b3e62ca974a5ea"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-6" >:: (fun _ -> assert_equal "f6e062ff507458f9be50497656ed654c"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-7" >:: (fun _ -> assert_equal "f6ed49f950e06576be74624c565058ff"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-7" >:: (fun _ -> assert_equal "d653a4696ca0bc0f5acaab5db96c5e7d"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-7" >:: (fun _ -> assert_equal "ebb19e1c3ee7c9e87d7535e9ed6b9144"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-7" >:: (fun _ -> assert_equal "d22f0c291ffe031a789d83b2ecc5364c"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-8" >:: (fun _ -> assert_equal "d2c5831a1f2f36b278fe0c4cec9d0329"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-8" >:: (fun _ -> assert_equal "7f074143cb4e243ec10c815d8375d54c"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-8" >:: (fun _ -> assert_equal "b951c33c02e9bd29ae25cdb1efa08cc7"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-8" >:: (fun _ -> assert_equal "2e6e7a2dafc6eef83a86ace7c25ba934"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-9" >:: (fun _ -> assert_equal "2e5bacf8af6ea9e73ac67a34c286ee2d"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-9" >:: (fun _ -> assert_equal "c357aae11b45b7b0a2c7bd28a8dc99fa"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-9" >:: (fun _ -> assert_equal "aeb65ba974e0f822d73f567bdb64c877"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-9" >:: (fun _ -> assert_equal "9cf0a62049fd59a399518984f26be178"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-10" >:: (fun _ -> assert_equal "9c6b89a349f0e18499fda678f2515920"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-10" >:: (fun _ -> assert_equal "1c05f271a417e04ff921c5c104701554"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-10" >:: (fun _ -> assert_equal "b2822d81abe6fb275faf103a078c0033"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-10" >:: (fun _ -> assert_equal "88db34fb1f807678d3f833c2194a759e"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-11" >:: (fun _ -> assert_equal "884a33781fdb75c2d380349e19f876fb"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-11" >:: (fun _ -> assert_equal "975c66c1cb9f3fa8a93a28df8ee10f63"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-11" >:: (fun _ -> assert_equal "810dce0cc9db8172b3678c1e88a1b5bd"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-11" >:: (fun _ -> assert_equal "ad9c7e017e55ef25bc150fe01ccb6395"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-12" >:: (fun _ -> assert_equal "adcb0f257e9c63e0bc557e951c15ef01"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-12" >:: (fun _ -> assert_equal "1859fbc28a1c00a078ed8aadc42f6109"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-12" >:: (fun _ -> assert_equal "bd2a395d2b6ac438d192443e615da195"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-12" >:: (fun _ -> assert_equal "84e1fd6b1a5c946fdf4938977cfbac23"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-13" >:: (fun _ -> assert_equal "84fb386f1ae1ac97df5cfd237c49946b"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-13" >:: (fun _ -> assert_equal "4f63760643e0aa85efa7213201a4e705"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-13" >:: (fun _ -> assert_equal "5f72641557f5bc92f7be3b291db9f91a"
                      (inv_add_round_key ist_256; get_data ist_256));
    "imix3-13" >:: (fun _ -> assert_equal "6353e08c0960e104cd70b751bacad0e7"
                      (inv_mix_cols ist_256; get_data ist_256));
    "ishift3-14" >:: (fun _ -> assert_equal "63cab7040953d051cd60e0e7ba70e18c"
                        (inv_shift_rows ist_256; get_data ist_256));
    "isub3-14" >:: (fun _ -> assert_equal "00102030405060708090a0b0c0d0e0f0"
                      (inv_sub_bytes ist_256; get_data ist_256));
    "iadd3-14" >:: (fun _ -> assert_equal "00112233445566778899aabbccddeeff"
                      (inv_add_round_key ist_256; get_data ist_256));


    (* full cipher *)
    "cipher1" >:: (fun _ -> assert_equal "69c4e0d86a7b0430d8cdb78070b4c55a"
                      (cipher_AES "00112233445566778899aabbccddeeff"
                        "000102030405060708090a0b0c0d0e0f"));
    "cipher2" >:: (fun _ -> assert_equal "dda97ca4864cdfe06eaf70a0ec0d7191"
                      (cipher_AES "00112233445566778899aabbccddeeff"
                        "000102030405060708090a0b0c0d0e0f1011121314151617"));
    "cipher3" >:: (fun _ -> assert_equal "8ea2b7ca516745bfeafc49904b496089"
                      (cipher_AES "00112233445566778899aabbccddeeff"
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    (* full decipher *)
    "decipher1" >:: (fun _ -> assert_equal "00112233445566778899aabbccddeeff"
                      (decipher_AES "69c4e0d86a7b0430d8cdb78070b4c55a"
                        "000102030405060708090a0b0c0d0e0f"));
    "decipher2" >:: (fun _ -> assert_equal "00112233445566778899aabbccddeeff"
                      (decipher_AES "dda97ca4864cdfe06eaf70a0ec0d7191"
                        "000102030405060708090a0b0c0d0e0f1011121314151617"));
    "decipher3" >:: (fun _ -> assert_equal "00112233445566778899aabbccddeeff"
                      (decipher_AES "8ea2b7ca516745bfeafc49904b496089"
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
  ]

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

(* [pad str] concatenates the hex equivalent of empty strings to hex string
 * [str] until it has a multiple of 32
 * requires: [str] must have even length *)
let rec pad str =
  if (String.length str) mod 32 = 0 then str
  else pad (str^"20")

let num_rand_tests = 50

let random_tests =
  print_endline "Please wait, generating random tests";
  let r_tests = ref [] in
  for i = 1 to num_rand_tests + 1 do
    let str_len = 2 + 2*(Random.int 50) in
    let key_len = 32 + (Random.int 3)*16 in
    let s = ref "" in
    for j = 1 to str_len do
      s := !s ^ (Char.escaped (int_to_hex_ch (Random.int 16)))
    done;
    let key = ref "" in
    for k = 1 to key_len do
      key := !key ^ (Char.escaped (int_to_hex_ch (Random.int 16)))
    done;
    let out = decipher_AES (cipher_AES !s !key) !key in
    r_tests := ("rand" ^ (string_of_int i) >:: (fun _ -> assert_equal (pad !s) out))::!r_tests
  done; !r_tests


let suite = "Test Suite" >::: tests @ random_tests

let _ = run_test_tt_main suite
