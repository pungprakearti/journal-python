#!/usr/bin/env python3
# Change this to point to your venv and it can run without sourcing the venv
# ex: #!/Users/<USER>/bin/journal/venv/bin/python3

'''
journal.py is a script that encrypts and decrypts journal entries
by: Andrew Pungprakearti
https://github.com/pungprakearti
https://www.linkedin.com/in/andrewpungprakearti/
http://www.biscuitsinthebasket.com
'''

import getpass
import bcrypt
from Crypto.Cipher import AES
import os
from datetime import date
from datetime import datetime
import sys


# Globals
IV = 'Python Journal!!'
KEY = ''
PASSWORD = ''
HASHED_PASSWORD = ''

# Journal path for storing entries in one place and being able to call
# the script from anywhere
# ex: '/Users/<USER>/Documents' or '.'
JOURNAL_PATH = '.'

print(f'{JOURNAL_PATH}/journal')

def out(mode, message):
    ''' Print messages in special colors '''

    warn = '\033[31m' # Red
    success = '\033[96m' # Cyan
    question = '\033[95m' # Purple
    reset = '\033[00m'

    if(mode == 'warn'):
        print(f'{warn}{message}{reset}')

    if(mode == 'success'):
        print(f'{success}{message}{reset}')

    # This is for inputs
    if(mode == 'question'):
        return input(f'{question}{message}{reset}')


def create_password():
    ''' Create main password to protect journal entries '''

    global KEY
    global PASSWORD

    # Create Journal directories
    if(not os.path.exists(f'{JOURNAL_PATH}/journal')):
        os.mkdir(f'{JOURNAL_PATH}/journal')

    if(not os.path.exists(f'{JOURNAL_PATH}/journal/entries')):
        os.mkdir(f'{JOURNAL_PATH}/journal/entries')

    # Create a new password
    password = getpass.getpass('Please enter a new password: ')
    confirm_password = getpass.getpass('Please confirm your password: ')

    if(password == confirm_password):
        out('success', 'PASSWORD CONFIRMED')

        # Save password locally in secret and assign to global
        PASSWORD = password
        save_password_local(password)

        # Assign as global
        KEY = pad_string(PASSWORD, 'key')

    else:
        out('warn', 'ERROR: THOSE PASSWORDS DO NOT MATCH\n')
        create_password()


def get_password():
    ''' Get password and verify '''

    global KEY
    global PASSWORD

    # Get password and assign to global
    password = getpass.getpass('Please enter your password: ')
    print('')
    PASSWORD = password

    if(password_verify()):
        # Assign as global
        KEY = pad_string(PASSWORD, 'key')

    else:
        out('warn', 'UNAUTHORIZED: PASSWORD INCORRECT')
        exit()


def save_password_local(password):
    ''' Saves a hashed password in secrets file '''

    # hash password
    global HASHED_PASSWORD
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(8))
    HASHED_PASSWORD = hashed_password.decode('utf-8')

    # save to binary file
    secret_file = open(f'{JOURNAL_PATH}/journal/secret', 'wb')
    secret_file.write(hashed_password)
    secret_file.close()

    out('success', '\nNEW PASSWORD SAVED')


def password_verify():
    ''' Reads secret file and check's hash against entered password '''

    # Read secret file
    secret_file = open(f'{JOURNAL_PATH}/journal/secret', 'rb')
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
        if(len(string) > 96):
            formatted = string[:96]
        else:
            formatted = (string + '                                                                                                ')[:96]

    # Journal entry
    else:
        padding = '                '[:(16 - (len(string) % 16))]
        formatted = string + padding

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

    return decrypted_message.decode('utf-8')


def create_entry():
    ''' Check for entry date and if file exists, add entry to it '''

    get_password()

    today = date.today()
    readable_date = today.strftime('%B %d, %Y')
    now = datetime.now()
    current_time = now.strftime('%H:%M:%S')
    filename = today.strftime('%Y%m%d') + now.strftime('%H%M%S')

    # Get new entry
    new_entry = out('question', f'{readable_date}: {current_time} - ')
    new_entry = f'{readable_date}: {current_time} - ' + new_entry

    # Read index and place new entry before old data
    if(os.path.exists(f'{JOURNAL_PATH}/journal/index')):
        index = open(f'{JOURNAL_PATH}/journal/index', 'rb')
        old_entries = decrypt(index.read())
        index.close()
    else:
        old_entries = ''

    new_entry_padded = pad_string(new_entry, 'snippet')
    index_text = pad_string(new_entry_padded + '\n' + old_entries)

    index = open(f'{JOURNAL_PATH}/journal/index', 'wb')
    index.write(encrypt(index_text))
    index.close()

    # Create entry file
    entry_file = open(f'{JOURNAL_PATH}/journal/entries/{filename}', 'wb')
    entry_to_write = pad_string(new_entry)
    entry_file.write(encrypt(entry_to_write))
    entry_file.close()

    out('success', '\nENTRY CREATED AND ENCRYPTED')


def list_entries():
    '''
    List all entries with snippets and have user select which
    entry to show.
    '''

    get_password()

    # Read index file and list entries
    index = open(f'{JOURNAL_PATH}/journal/index', 'rb')
    index_contents = decrypt(index.read())
    index.close()
    index_sections = index_contents.split('\n')

    i = 1
    for section in index_sections[:-1]:
        print(f'\033[95m{i}.\033[00m {section}')
        i += 1

    choice = out('question', '\nPlease select an entry to read: ')

    # convert choice to integer
    try:
        choice = int(choice)
    except ValueError:
        out('warn', 'ERROR: Your choice should be a listed number')
        exit()

    if(choice > 0 and choice < len(index_sections)):
        read_entry(choice)
    else:
        out('warn', 'ERROR: Your choice should be a listed number')


def read_entry(entry_number):
    ''' Use entry number to decrupt that entry in the entries folder '''

    # Get all entry files and sort them in reverse order
    entries = os.listdir(f'{JOURNAL_PATH}/journal/entries')

    if(len(entries) < 1):
        out('warn', 'ERROR: There are no entries')
        exit()

    entries.sort(reverse=True)

    # Open, decrypt and print contents of entry
    entry_file = open(f'{JOURNAL_PATH}/journal/entries/{entries[entry_number - 1]}', 'rb')
    entry = entry_file.read()
    entry_file.close()
    entry_decrypted = decrypt(entry)
    entry_list = entry_decrypted.split(' - ')

    print('\n\033[96m' + entry_list[0] + ' - \033[00m' + entry_list[1] + '\n')


def print_help():
    ''' Print the help dialog '''

    print('''\n./journal.py <option>
------------------------------------------------------
\033[95mhelp, h, ?\033[00m              Display this menu
\033[95mcreate\033[00m                  Create a new journal entry
\033[95mlist\033[00m                    List all entries with snippets
\033[95mread <list number>\033[00m      Display entry
''')


##################################################################################################
''' Run script '''

options = {
    'help': print_help,
    'h': print_help,
    '?': print_help,
    'create': create_entry,
    'list': list_entries,
    'read': read_entry
}

if(os.path.exists(f'{JOURNAL_PATH}/journal/secret')):
    if(len(sys.argv) == 1):
        print_help()

    if(len(sys.argv) == 2):
        try:
            options[sys.argv[1]]()
        except KeyError:
            out('warn', 'ERROR: That operation does not exist')
            print_help()

else:
    out('success', 'INITIALIZING JOURNAL')
    create_password()
