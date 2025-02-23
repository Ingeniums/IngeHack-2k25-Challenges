#!/usr/bin/python3

FLAG = open('flag.txt').read()

whitelist = [ 
	'-', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 
	'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '`', 'a', 'b', 'c', 'd', 'e', 
	'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z', '~',
	'!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '/', ':', '=', '?', '@',
]

print("your classic python jail")
while True:
	pay = input("$ ")
	for i in pay:
		if i not in whitelist:
			print("nope")
			exit(0)
	for i in pay:
		if (len(set(pay))>17):
			print("nope")
			exit(0)
	try:
		eval(pay, { '__builtins__': None, 'ord': ord, 'flag': FLAG })
		print("nope")
	except Exception as e:
		print("yup")