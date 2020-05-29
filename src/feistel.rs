use crate::hasher::{EncryptErr, hash_xor_key, pad, pad_key};

pub fn encrypt(mut msg: Vec<u8>, mut key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, EncryptErr>{
    //assertions
    pad(&mut msg, 128);
    pad_key(&mut key, 64);
    for _ in 0..rounds {
        println!("msg {:?}\n{}", msg, msg.len());
        println!("key {:?}\n{}", key, key.len());
        fiestel_round(&mut msg, &key)?;
        inc_key(&mut key);
    }
    swap(&mut msg);
    Ok(msg)
}

pub fn decrypt(mut msg: Vec<u8>,  mut key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, EncryptErr>{
    //assertions
    pad_key(&mut key, 64);
    swap(&mut msg);
    println!("msg {:?}\n{}", msg, msg.len());
    println!("key {:?}\n{}", key, key.len());
    let mut final_key = calc_final_key(&key, rounds);
    for _ in 0..rounds {
        fiestel_round(&mut msg, &final_key)?;
        dec_key(&mut final_key);
    }
    Ok(msg)
}


pub fn fiestel_round<'a >(msg: &'a mut Vec<u8>, k: &'a Vec<u8>) -> Result<(), EncryptErr> {
    assert!(msg.len() == 128, "msg should be 2X256bits / 128 bytes");
    assert!(k.len() == 64, "key should be 256bits / 64 bytes");
    
    let right = msg.split_off(msg.len()/2);
    println!("right {:?}\n{}", right, right.len());
    println!("left {:?}\n{}", msg, msg.len());
    let mut f_of_right = f_func(&mut right.clone(), k)?;
    println!("f(right) {:?}\n{}", f_of_right, f_of_right.len());
    msg.iter_mut().zip(f_of_right.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    f_of_right.append(msg);
    *msg = f_of_right;
    Ok(())
}

fn f_func(v: &mut Vec<u8>, k: &Vec<u8>) -> Result<Vec<u8>, EncryptErr>{
    hash_xor_key(v, &mut k.clone())
}

fn inc_key(k: &mut Vec<u8>){
    k.iter_mut().for_each(|x| *x += 1);
}

fn dec_key(k: &mut Vec<u8>){
    k.iter_mut().for_each(|x| *x -= 1);

}

fn calc_final_key(k: &Vec<u8>, rounds: i32) -> Vec<u8>{
    let mut final_key = k.clone();
    for _ in 0..rounds{
        inc_key(&mut final_key)
    }
    final_key
}

pub fn swap(msg: &mut Vec<u8>){
    let mut s = msg.split_off(msg.len()/2);
    s.append(msg);
    *msg = s;
}

