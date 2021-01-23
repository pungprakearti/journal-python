#!/usr/bin/env python3

'''
journal.py is script that encodes a journal/text file using a key
'''

import getpass
import bcrypt
from Crypto.Cipher import AES
import os
import os.path
from os import path
from datetime import date
from datetime import datetime
import sys


# Globals
IV = 'Python Journal!!'
KEY = ''
PASSWORD = ''
HASHED_PASSWORD = ''

def get_password():
    '''
    Check if password already exists and if not,
    create a new password for the journal.
    If password exists, get password from user to verify
    '''

    global KEY
    global PASSWORD

    if(path.exists('./journal/secret')):
        # Get password and assign to global
        password = getpass.getpass('Please enter your password: ')
        PASSWORD = password

        if(password_verify()):
            print('WE DID IT')

            # Assign as global
            KEY = format_to_16(PASSWORD)

        else:
            print('UNAUTHORIZED: PASSWORD INCORRECT')

    else:
        # Create Journal directory
        os.mkdir('./journal')

        # Get a new password
        password = getpass.getpass('Please enter a new password: ')
        confirm_password = getpass.getpass('Please confirm your password: ')

        if(password == confirm_password):
            print('PASSWORD CONFIRMED')

            # Save password locally
            PASSWORD = password
            save_password_local(password)

            # Assign as global
            KEY = format_to_16(password)

        else:
            print('ERROR: THOSE PASSWORDS DO NOT MATCH\n')
            get_password()


def save_password_local(password):
    ''' Saves a hashed password in secrets file '''

    # hash password
    global HASHED_PASSWORD
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(8))
    HASHED_PASSWORD = hashed_password.decode('utf-8')

    # save to binary file
    secret_file = open('./journal/secret', 'wb')
    secret_file.write(hashed_password)
    secret_file.close()

    print('NEW PASSWORD SAVED')


def password_verify():
    ''' Reads secret file and check's hash against entered password '''

    # Read secret file
    secret_file = open('./journal/secret', 'rb')
    local_hashed_password = secret_file.read()

    if(bcrypt.checkpw(PASSWORD.encode('utf-8'), local_hashed_password)):
        return True
    else:
        return False


def create_journal():
    ''' Create the initial journal, store the hashed password in it and encode '''

    # Create main journal file
    journal_header = encrypt(pad_message(HASHED_PASSWORD))
    journal_file = open('./journal/journal', 'wb')
    journal_file.write(journal_header)
    journal_file.close()

    # Create entries folder
    os.mkdir('./journal/entries')

    print('JOURNAL CREATED')


def pad_message(message, empty_line = False):
    '''
    Messages have to be multiples of 16 in order to encrypt
    Adds necessary padding to the message
    '''

    if(empty_line):
        padding = '                '[:(14 - (len(message) % 16))]
        padded_message = message + padding + '\n\n'
    else:
        padding = '                '[:(15 - (len(message) % 16))]
        padded_message = message + padding + '\n'

    return padded_message


def format_to_16(string):
    ''' Format the string to 16 characters '''

    if(len(string) > 16):
        formatted = string[:16]
    else:
        formatted = (string + '                ')[:16]

    return formatted


def encrypt(message):
    ''' Encrypt a message using AES '''

    cipher_encrypt = AES.new(KEY, AES.MODE_CBC, IV)
    cipher_text = cipher_encrypt.encrypt(message)

    return cipher_text


def decrypt(message):
    ''' Decrypt an AES message '''

    cipher_decrypt = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_message = cipher_decrypt.decrypt(message)

    print(decrypted_message.decode('utf-8'))

    return decrypted_message


def create_entry():
    ''' Check for entry date and if file exists, add entry to it '''

    today = date.today()
    filename = today.strftime('%Y%m%d')
    readable_date = today.strftime('%B %d, %Y')
    now = datetime.now()
    current_time = now.strftime('%H:%M:%S')


    if(path.exists(f'./journal/entries/{readable_date}')):
        print('it exists')

    else:
        # File doesn't exist so create new entry file with date header
        current_entry = f'{readable_date}:\n{current_time} - '
        new_entry = input(f'{current_time} - ')
        current_entry += new_entry

        # Encrypt entry
        padded_entry = pad_message(current_entry, True)
        encrypted_entry = encrypt(padded_entry)
        
        # Write to file
        entry_file = open(f'./journal/entries/{filename}', 'wb')
        entry_file.write(encrypted_entry)
        entry_file.close()


def print_help():
    ''' Print the help dialog '''

    print('''\n./journal.py <option>
------------------------------------------------------
help, h, ?              Display this menu
create                  Create a new journal entry
list                    List all entries with snippets
read <list number>      Display entry
''')


def list_entries():
    print('list entries')


def read_entry(entry_number):
    print('read entry')    


#################################################

# Verify current password of if none exists, create a new one
# get_password()

# Create initial journal file and directory
# if(not path.exists('./journal/journal')):
    # create_journal()

# Create entry
# create_entry()

options = {
    'help': print_help,
    'h': print_help,
    '?': print_help,
    'create': create_entry,
    'list': list_entries,
    'read': read_entry
}

if(path.exists('./journal/secret')):
    if(len(sys.argv) == 1):
        print_help()

    if(len(sys.argv) == 2):
        options[sys.argv[2]]

else:
    print('INITIALIZING JOURNAL')
    get_password()

'''
journal file
first line is hash
every line after that is path to files
files organized by date 20210122
'''
