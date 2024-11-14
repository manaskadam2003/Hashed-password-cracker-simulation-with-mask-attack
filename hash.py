import hashlib
import os
import itertools
import string
from concurrent.futures import ThreadPoolExecutor
import time

# Supported hash algorithms and their lengths
HASH_ALGORITHMS = {
    32: 'md5',
    40: 'sha1',
    64: 'sha256'
}

def detect_hash_algorithm(hash_str):
    """Detect the hash algorithm based on hash length."""
    length = len(hash_str)
    return HASH_ALGORITHMS.get(length, 'sha256')  # Default to sha256 if unknown length

def hash_password(password: str, algorithm: str = 'sha256') -> str:
    """Hashes a password with the specified algorithm."""
    hasher = hashlib.new(algorithm)
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def dictionary_attack(hash_to_crack: str, wordlist: str, algorithm: str = 'sha256') -> str:
    """Attempts to crack a hash using a wordlist (dictionary attack)."""
    try:
        with open(wordlist, 'r') as file:
            for word in file:
                word = word.strip()
                hashed_word = hash_password(word, algorithm)
                if hashed_word == hash_to_crack:
                    return word  # Password found
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist}' not found.")
    return None  # Password not found

def attempt_password(guess, hash_to_crack, algorithm):
    """Helper function for parallel processing in brute-force attack."""
    if hash_password(guess, algorithm) == hash_to_crack:
        return guess
    return None

def brute_force_attack_parallel(hash_to_crack: str, algorithm: str, max_length: int) -> str:
    """Attempts to crack a hash using a brute-force attack with multithreading."""
    characters = string.ascii_lowercase + string.digits
    start_time = time.time()
    with ThreadPoolExecutor() as executor:
        for length in range(1, max_length + 1):
            print(f"Trying length {length}...")
            for guess_tuple in itertools.product(characters, repeat=length):
                guess = ''.join(guess_tuple)
                future = executor.submit(attempt_password, guess, hash_to_crack, algorithm)
                result = future.result()
                if result:
                    print(f"Time taken: {time.time() - start_time:.2f} seconds")
                    return result
    print(f"Brute-force completed in {time.time() - start_time:.2f} seconds without success.")
    return None

def mask_based_attack(hash_to_crack: str, algorithm: str, mask: str) -> str:
    """Attempts to crack a hash using a mask-based brute force approach."""
    
    # Character sets for each mask symbol
    mask_options = {
        'L': string.ascii_lowercase,   # Lowercase letters (a-z)
        'U': string.ascii_uppercase,   # Uppercase letters (A-Z)
        'D': string.digits,            # Digits (0-9)
        'S': string.punctuation,       # Special characters (!, @, #, $, etc.)
        'A': string.ascii_letters + string.digits + string.punctuation  # Alphanumeric + Special characters
    }
    
    # Prepare the patterns for each character in the mask
    guess_patterns = []
    for char in mask:
        if char in mask_options:
            guess_patterns.append(mask_options[char])  # Add the corresponding character set
        else:
            guess_patterns.append(char)  # Add the literal character (e.g., fixed characters)

    start_time = time.time()
    
    # Generate all combinations based on the mask
    with ThreadPoolExecutor() as executor:
        for guess_tuple in itertools.product(*guess_patterns):
            guess = ''.join(guess_tuple)
            if hash_password(guess, algorithm) == hash_to_crack:
                print(f"Password found using mask in {time.time() - start_time:.2f} seconds")
                return guess
    
    print(f"Mask-based attack completed in {time.time() - start_time:.2f} seconds without success.")
    return None

def attack_page(hash_to_crack, algorithm):
    """Allows the user to choose an attack type and perform the attack until they succeed or choose to go back."""
    while True:
        print("\nChoose the attack type:")
        print("1. Dictionary Attack (using wordlist)")
        print("2. Brute-Force Attack (up to a specified length)")
        print("3. Mask-Based Attack (using a defined character pattern)")
        attack_choice = input("Enter your choice (1, 2, or 3): ")

        if attack_choice == '1':
            # Dictionary Attack
            wordlist = input("Enter the path to the wordlist file: ")
            password = dictionary_attack(hash_to_crack, wordlist, algorithm)
            
            if password:
                print(f"Password found: {password} using Dictionary Attack.")
                return password  # Exit after finding password
            else:
                print("Password not found in the wordlist. Try again.")
        
        elif attack_choice == '2':
            # Brute-Force Attack with Multithreading
            max_length = int(input("Enter the maximum length of password to attempt (e.g., 4): "))
            print("Attempting brute-force attack. This may take a while...")
            password = brute_force_attack_parallel(hash_to_crack, algorithm, max_length)
            
            if password:
                print(f"Password found: {password} using Brute-Force Attack.")
                return password  # Exit after finding password
            else:
                print("Password not found with brute-force attack. Try again.")
        
        elif attack_choice == '3':
            # Mask-Based Attack
            print("Define mask with L for lowercase, U for uppercase, D for digits, or a specific character.")
            print("Example mask: LLDD would test two lowercase letters followed by two digits.")
            mask = input("Enter the mask: ")
            print("Attempting mask-based attack...")
            password = mask_based_attack(hash_to_crack, algorithm, mask)
            
            if password:
                print(f"Password found: {password} using Mask-Based Attack.")
                return password  # Exit after finding password
            else:
                print("Password not found with mask-based attack. Try again.")
        
        else:
            print("Invalid attack choice. Please enter 1, 2, or 3.")

def main():
    while True:
        print("\nChoose an option:")
        print("1. Hash a password")
        print("2. Crack a password hash")
        print("3. Exit")
        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == '1':
            password = input("Enter the password to hash: ")
            algorithm = input("Enter the hashing algorithm (e.g., md5, sha1, sha256): ").lower()
            
            try:
                hashed_password = hash_password(password, algorithm)
                print(f"Hashed password ({algorithm}): {hashed_password}")
            except ValueError:
                print(f"Error: '{algorithm}' is not a supported hashing algorithm.")

        elif choice == '2':
            hash_to_crack = input("Enter the hash to crack: ")
            algorithm = detect_hash_algorithm(hash_to_crack)
            print(f"Detected hash algorithm: {algorithm}")
            
            # Call the attack page to let user choose attack type and perform until success
            password = attack_page(hash_to_crack, algorithm)
            if password:
                print(f"Password cracked: {password}. Exiting program now.")
                break  # Exit the program after finding the password
        
        elif choice == '3':
            print("Exiting program.")
            break  # Exit the program

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if _name_ == "_main_":
    main()
