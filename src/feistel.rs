use crate::hasher::EncryptErr;

pub fn encrypt(mut msg: Vec<u8>, mut key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, EncryptErr>{
    //assertions

    for _ in 0..rounds {
       fiestel_round(&mut msg, &key)?;
        inc_key(&mut key);
    }
    swap(&mut msg);
    Ok(msg)
}

pub fn decrypt(mut msg: Vec<u8>,  key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, EncryptErr>{
    //assertions

    swap(&mut msg);
    let mut final_key = calc_final_key(&key, rounds);
    for _ in 0..rounds {
        fiestel_round(&mut msg, &final_key)?;
        dec_key(&mut final_key);
    }
    Ok(msg)
}


fn fiestel_round<'a >(msg: &'a mut Vec<u8>, k: &'a Vec<u8>) -> Result<(), EncryptErr> {
    assert!(msg.len() > 0, "msg is of length 0");
    assert!(k.len() > 0, "key is of length 0");
    assert!(msg.len()%2 == 0, "msg length not even");
    assert!(k.len() < msg.len() / 2, "key too big");

    let mut right = msg.split_off(msg.len()/2);
    let f_of_right = f_func(&mut right.clone(), k);
    msg.iter_mut().zip(f_of_right.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    right.append(msg);
    *msg = right;
    Ok(())
}

fn f_func(v: &mut Vec<u8>, k: &Vec<u8>) -> Vec<u8>{
    Vec::new()
}

fn break_msg(msg: &mut Vec<u8>) -> (Vec<u8>, Vec<u8>){
    (Vec::new(), Vec::new())
}

fn inc_key(k: &mut Vec<u8>){
}

fn dec_key(k: &mut Vec<u8>){
}

fn calc_final_key(k: &Vec<u8>, rounds: i32) -> Vec<u8>{
    Vec::new()
}



pub fn swap(msg: &mut Vec<u8>){
    let mut s = msg.split_off(msg.len()/2);
    s.append(msg);
    *msg = s;
}

