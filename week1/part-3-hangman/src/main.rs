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
use std::collections::HashMap;

const NUM_INCORRECT_GUESSES: u32 = 5;
const WORDS_PATH: &str = "words.txt";

fn pick_a_random_word() -> String {
    let file_string = fs::read_to_string(WORDS_PATH).expect("Unable to read file.");
    let words: Vec<&str> = file_string.split('\n').collect();
    String::from(words[rand::thread_rng().gen_range(0, words.len())].trim())
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
    println!("Welcome to CS110L Hangman!");
    let mut word: Vec<char> = Vec::new();
    let mut i = 0;
    while i < secret_word_chars.len() {
        word.push('-');
        i += 1;
    }
    let mut map: HashMap<char, i32> = HashMap::new();
    for ch in secret_word_chars.iter() {
        *map.entry(*ch).or_insert(0) += 1;
    }

    let mut word_guessed: Vec<char> = Vec::new();
    let mut guess_remain = NUM_INCORRECT_GUESSES;
    
    loop {
        if guess_remain == 0 {
            println!("Sorry, you ran out of guesses!");
            break;
        }
        
        let tmps: String = word.iter().collect();
        println!("The word so far is {}", tmps);
        let tmps: String = word_guessed.iter().collect();
        println!("You have guessed the following letters: {}", tmps);
        println!("You have {} guesses left", guess_remain);

        print!("Please guess a letter: ");
        io::stdout().flush().expect("Error flushing stdout.");
        let mut guess = String::new();
        io::stdin().read_line(&mut guess).expect("Error reading line.");
        if guess.trim().chars().count() != 1 {
            // println!("{} {}", guess, guess.trim().chars().count());
            println!("Please guess one letter only!\n");
            continue;
        }
        let letters: Vec<char> = guess.trim().chars().collect();
        let letter = letters[0];
        word_guessed.push(letter);

        if map.contains_key(&letter) {
            *map.entry(letter).or_insert(0) -= 1;
            if *map.get(&letter).expect("Error here") == 0 {
                map.remove(&letter);
            }

            let mut idx = 0;
            while idx < secret_word_chars.len() {
                if secret_word_chars[idx] == letter && word[idx] == '-' {
                    word[idx] = letter;
                    break;
                }
                idx += 1;
            }
        } else {
            guess_remain -= 1;
            println!("Sorry, that letter is not in the word");
        }
        
        if map.len() == 0 {
            let tmps: String = word.iter().collect();
            println!("Congratulations you guessed the secret word: {}!",
                    tmps);
            break;
        }
        print!("\n");
    }
    
}
