// Simple Hangman Program
// User gets five incorrect guesses
// Word chosen randomly from words.txt
// Inspiration from: https://doc.rust-lang.org/book/ch02-00-guessing-game-tutorial.html
// This assignment will introduce you to some fundamental syntax in Rust:
// - variable declaration
// - string manipulation
// - conditional statements
// - loops
// - vectors
// - files
// - user input
// We've tried to limit/hide Rust's quirks since we'll discuss those details
// more in depth in the coming lectures.
extern crate rand;

use rand::Rng;
use std::fs;
use std::io;
use std::io::Write;
use std::collections::{HashMap, HashSet};
use std::vec;

const NUM_INCORRECT_GUESSES: u32 = 5;
const WORDS_PATH: &str = "words.txt";

fn pick_a_random_word() -> String {
    let file_string = fs::read_to_string(WORDS_PATH).expect("Unable to read file.");
    let words: Vec<&str> = file_string.split('\n').collect();
    String::from(words[rand::thread_rng().gen_range(0, words.len())].trim())
}

fn get_guess() -> Result<char, &'static str> {
    print!("Please guess a letter: ");
    // Make sure the prompt from the previous line gets displayed:
    io::stdout()
        .flush()
        .expect("Error flushing stdout.");
    let mut guess = String::new();
    io::stdin()
        .read_line(&mut guess)
        .expect("Error reading line.");
    let guess = guess.strip_suffix("\n").unwrap();
    if guess.len() != 1{
        return Err("You can only input a letter");
    }
    return Ok(guess.chars().nth(0).unwrap());
}

fn main() {
    let secret_word = pick_a_random_word();
    // Note: given what you know about Rust so far, it's easier to pull characters out of a
    // vector than it is to pull them out of a string. You can get the ith character of
    // secret_word by doing secret_word_chars[i].
    let secret_word_chars: Vec<char> = secret_word.chars().collect();
    // Uncomment for debugging:
    println!("random word: {}", secret_word);

    // Your code here! :)
    let mut current_guess_chars = Vec::with_capacity(secret_word_chars.len());
    for i in 0..secret_word_chars.len(){
        current_guess_chars.push('-' as u8);
    }

    let mut map: HashMap<char, Vec<i32>> = HashMap::new();
    for i in 0..secret_word_chars.len(){
        let character= secret_word_chars[i];
        if map.contains_key(&character){
            let mut vec = map.get_mut(&character).unwrap();
            vec.push(i as i32);
        } else{
            map.insert(character, vec![i as i32]);
        }
    }

    let mut chances = 5;
    let mut unknown = secret_word_chars.len();
    let mut guessed_vec:Vec<u8> = Vec::new();

    while chances != 0 && unknown != 0{
        let current_guess = String::from_utf8(current_guess_chars.clone()).unwrap();
        let guessed = String::from_utf8(guessed_vec.clone()).unwrap();
        println!("The word so far is {}", current_guess);
        println!("You have guessed the following letters: {}", guessed);
        println!("You have {} guesses left", chances);
        let my_guess = match get_guess(){
            Ok(c) => c,
            Err(e) => {println!("{}", e); continue;}
        };
        guessed_vec.push(my_guess as u8);
        if map.contains_key(&my_guess){
            let v = map.get_mut(&my_guess).unwrap();
            let idx = v.pop().unwrap();
            if v.len() == 0{
                map.remove(&my_guess);
            }
            current_guess_chars[idx as usize] = my_guess as u8;
            unknown -= 1;
        } else{
            chances -= 1;
            continue
        }
    }

    if chances == 0{
        println!("Sorry, you ran out of guesses!");
    } else if unknown == 0{
        println!("Congratulations you guessed the secret word: {}!", secret_word);
    }
    return;
}
