import requests
import hashlib
import sys


# converts password to hex, utf-8 and runs other functions
def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # must be in hex and utf-8
    first_5_chars, tail = sha1_password[:5], sha1_password[5:]  # first 5 characters are checked
    response = request_api_data(first_5_chars)  # k-anonymite
    return password_leaks_count(response, tail)


# returns suffix with count how many times it was pawned
def request_api_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error: {response.status_code}. Check the API!')
    return response


# checks our suffix with suffix which was returned and returns count
def password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())  # splits lines
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def main(file_name):
    # text file with passwords
    with open(file_name) as file_in:
        lines = [item.rstrip() for item in file_in.readlines()]  # readlines returns list of lines, rstrip deletes \n
        for password in lines:
            count = pwned_api_check(password)  # checking
            if count:
                print(f'{password} was found {count} times... you should change it.')
            else:
                print(f'{password} was not found. Good for you!!!')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))

'''
less secure way
passwords are passed through terminal
def main(args):
    for password in arg:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should change it.')
        else:
            print(f'{password} was not found. Good for you!!!')
    


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
'''
