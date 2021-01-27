# Pyairy
A password protected Python3 diary that encrypts your entries  

# Getting started
## Install Python3  
Download it here: https://www.python.org/downloads/

## Install Pip
`python3 -m ensurepip`

## Create Python virtual environment
`python3 -m venv venv`

## Activate venv
`source venv/bin/activate`

## Install modules
`pip3 install -r requirements.txt`

## Make the script executable
`chmod a+x ./pyairy.py`  

## Create password
`./pyairy.py`  

Then enter a password to protect your entries  

# Pyairy operations  
All arguments are ran with `./pyairy.py <operation>`  

## create
Create an entry  

## list
Lists all entries as small snippets and prompts you to select an entry to decrypt and read  

## help
Displays all of these operations  

# How it works
BCrypt is used to hash your password which is then stored locally.  

PyCrypto encrypts and decrypts your entries after verifying your password with BCrypt.  

Your password is stored as a hash so that no one can determine what your password is as plain text.  

Your password is also used as a key to encrypt your entries.

The password is always verified before encryption so that your entries always use the same key.

# Usage tips
## Getting around sourcing your terminal
After you are all set up, you can edit the shebang to use your venv without having to source it everytime.  

`#!/usr/bin/env python3`  

Can be changed to:  

`#!/Users/<USER>/bin/pyairy/venv/bin/python3`

## Create a central location to store your entries
On line 31, assign a path to `DIR_PATH`  

I use `/Users/<USER>/Documents`  

## Create an alias to call Pyairy anywhere
`alias pyairy='/<ABSOLUTE_PATH_TO_PYAIRY>/pyairy.py'`