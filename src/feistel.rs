use hasher::EncryptErr;

pub fn encrypt(msg: Vec<u8>, key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, EncryptErr>{
    //assertions

    for _ in 0..rounds {
        msg = fiestel_round(&mut msg, &key)?;
        key = inc_key(&mut key)?;
    }
    swap(msg)
}

pub fn decrypt(msg: Vec<u8>, key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, EncryptErr>{
    //assertions
    
    swap(msg)
    let final_key = calc_final_key(&key, rounds);
    for _ in 0..rounds {
        msg = fiestel_round(&mut msg, &final_key)?;
        key = dec_key(&mut final_key)?;
    }
    msg
}


fn fiestel_round<'a >(msg: &'a mut Vec<u8>, k: &'a Vec<u8>) -> &'a mut Vec<u8> {
    assert!(msg.len() > 0, "msg is of length 0");
    assert!(k.len() > 0), "key is of length 0";
    assert!(msg.len()%2 == 0, "msg length not even");
    assert!(key.len() < msg.len() / 2, "key too big")

    let (left, right) = brake_msg(msg);
    let f_of_right = f_func(right.clone(), k);
    left.iter_mut().zip(f_of_right.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    right.append(&mut left)
}


fn break_msg(msg: &mut Vec<u8>) -> (Vec<u8>, Vec<u8>){

}

fn f_func(v: &mut Vec<u8>, k: &mut Vec<u8>) -> Vec<u8>{

}