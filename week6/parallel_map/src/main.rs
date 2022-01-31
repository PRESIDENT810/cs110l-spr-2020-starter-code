use crossbeam_channel;
use std::{thread, time};

fn parallel_map<T, U, F>(input_vec: Vec<T>, num_threads: usize, f: F) -> Vec<U>
    where
        F: FnOnce(T) -> U + Send + Copy + 'static,
        T: Send + 'static,
        U: Send + 'static + Default + Clone, {
    let mut output_vec: Vec<U> = vec![U::default(); input_vec.len()];
    // prepare channel
    let (operand_sender, operand_receiver) = crossbeam_channel::bounded::<(usize, T)>(input_vec.len());
    let (res_sender, res_receiver) = crossbeam_channel::bounded::<(usize, U)>(output_vec.len());
    // spawn threads
    for _i in 0..(num_threads-1){
        let my_receiver = operand_receiver.clone();
        let my_sender = res_sender.clone();
        thread::spawn(move || {
            loop {
                let result = my_receiver.recv();
                match result{
                    Ok((idx, num)) => {
                        let res = f(num);
                        my_sender.send((idx, res)).unwrap();
                    },
                    Err(_) => {
                        break;
                    }
                }
            }
        });
    }
    // send values to threads
    let mut idx = 0;
    for i in input_vec{
        operand_sender.send((idx, i)).unwrap();
        idx += 1;
    }
    // receive results
    let mut cnt = 0;
    loop{
        if cnt == output_vec.len(){
            break;
        }
        match res_receiver.recv(){
            Ok(res) => {
                output_vec[res.0] = res.1;
                cnt += 1;
            },
            Err(_) => {
                println!("error");
                break;
            }
        }
    }
    return output_vec;
}

fn main() {
    let v = vec![6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 12, 18, 11, 5, 20];
    let squares = parallel_map(v, 10, |num| {
        println!("{} squared is {}", num, num * num);
        thread::sleep(time::Duration::from_millis(500));
        num * num
    });
    println!("squares: {:?}", squares);
}
