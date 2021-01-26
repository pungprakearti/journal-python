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


def create_password():
    ''' Create main password to protect journal entries '''

    global KEY
    global PASSWORD

    # Create Journal directory
    if(not path.exists('./journal')):
        os.mkdir('./journal')

    # Create a new password
    password = getpass.getpass('Please enter a new password: ')
    confirm_password = getpass.getpass('Please confirm your password: ')

    if(password == confirm_password):
        print('PASSWORD CONFIRMED')

        # Save password locally in secret and assign to global
        PASSWORD = password
        save_password_local(password)

        # Assign as global
        KEY = pad_string(PASSWORD, 'key')

    else:
        print('ERROR: THOSE PASSWORDS DO NOT MATCH\n')
        create_password()


def get_password():
    ''' Get password and verify '''

    global KEY
    global PASSWORD

    # Get password and assign to global
    password = getpass.getpass('Please enter your password: ')
    PASSWORD = password

    if(password_verify()):
        # Assign as global
        KEY = pad_string(PASSWORD, 'key')

    else:
        print('UNAUTHORIZED: PASSWORD INCORRECT')
        exit()


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


def pad_string(string, mode='entry'):
    '''
    Messages have to be multiples of 16 in order to encrypt
    Adds necessary padding to the message
    '''

    # Key for encryption
    if(mode == 'key'):
        if(len(string) > 16):
            formatted = string[:16]
        else:
            formatted = (string + '                ')[:16]

    # Snippet for index
    elif(mode == 'snippet'):
        if(len(string) > 32):
            formatted = string[:32]
        else:
            formatted = (string + '                                ')[:32]

    # Journal entry
    else:
        padding = '                '[:(16 - (len(string) % 16))]
        formatted = string + padding

    return formatted


def encrypt(message):
    ''' Encrypt a message using AES '''

    print(message, len(message))

    cipher_encrypt = AES.new(KEY, AES.MODE_CBC, IV)
    cipher_text = cipher_encrypt.encrypt(message)

    return cipher_text


def decrypt(message):
    ''' Decrypt an AES message '''

    cipher_decrypt = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_message = cipher_decrypt.decrypt(message)

    return decrypted_message.decode('utf-8')

# NEED TO FIGURE OUT BETTER PADDING
# LENGTH IS IN CORRECT WHEN TRYING TO ENCRYPT
def create_entry():
    ''' Check for entry date and if file exists, add entry to it '''

    get_password()

    today = date.today()
    filename = today.strftime('%Y%m%d')
    readable_date = today.strftime('%B %d, %Y')
    now = datetime.now()
    current_time = now.strftime('%H:%M:%S')

    # Get new entry
    new_entry = input(f'{readable_date}: {current_time} - ')
    new_entry = f'{readable_date}: {current_time} - ' + new_entry

    # Read index and place new entry before old data
    if(path.exists('./journal/index')):
        index = open('./journal/index', 'rb')
        old_entries = decrypt(index.read())
        index.close()
    else:
        old_entries = ''

    new_entry_padded = pad_string(new_entry, 'snippet')
    index_text = pad_string(new_entry + '\n' + old_entries)

    index = open('./journal/index', 'wb')
    index.write(encrypt(index_text))
    index.close()

    # Create entry file
    '''
    entry_file = open(f'./journal/entries/{filename}', 'rb')
    old_entry_contents = entry_file.read()
    entry_file.close()

    entry_file = open(f'./journal/entries/{filename}', 'wb')
    old_entry_contents = decrypt(old_entry_contents)
    entry_to_write = pad_string(new_entry) + old_entry_contents
    entry_file.write(encrypt(entry_to_write))
    entry_file.close()
    '''


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
    get_password()

    index = open('./journal/index', 'rb')
    index_contents = decrypt(index.read())
    print('this is index: ', index_contents)
    index.close()


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
        options[sys.argv[1]]()

else:
    print('INITIALIZING JOURNAL')
    create_password()

'''
journal file
first line is hash
every line after that is path to files
files organized by date 20210122

save hashed password to verify because if we just encrypt with
any password, if the password is different, if will be very difficult
to retrieve your data
'''
