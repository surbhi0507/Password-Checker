import requests
import hashlib
import sys
# Idempotent = A function given an input always outputs the same output

def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	#print(res)
	
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again!')
	return res

# To learn more about the data that we learn from request_api_data function, we create this function
# def read_res(response):
# 	print(response.text) # we get all the hashed pass starting from first5_char

def get_pass_leaks_counts(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		#print(h, count)
		if h == hash_to_check:
			return count
	return 0


def check_pwned_api(password):
	# Check password if it exists in API response
	# Now we have to run our password through SHA-1 algo, luckily, py has a built in module hashlib
	# print(password.encode('utf-8'))
	
	# hash object converted into hexadecimal and then uppercase
	#print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
	
	#when we donot use utf8 - will throw an error
	#print(hashlib.sha1(password).hexdigest().upper())

	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

	# Next we are going to try and send sha1password to the api, w.k.t we only need 1st 5 chars of our hash password
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)
	#print(response)
	return get_pass_leaks_counts(response, tail)

#check_pwned_api('123')

def main(args):
	for password in args:
		count = check_pwned_api(password)
		if count:
			print(f'{password} was found {count} times... you should probably change your password!')
		else:
			print(f'{password} was NOT found. You are safe. Carry on!')
	return 'done!'

pass_list = []
with open('word_list.txt','r') as file:
    try:
        for password in file.readlines():
            pass_list.append(password.strip('\n'))
    except FileNotFoundError as err:
        print(f'File not found, error {err} ')

    main(pass_list)


if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))
