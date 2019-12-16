from Xifratges import mcd, generar_primer

print("\nENCRIPTACIÓ RSA")

while True:
	print("\nQuin procés dur a terme?")
	print("\n1 GENERAR CLAUS PÚBLIQUES I PRIVADA")
	print("\n2 ENCRIPTACIÓ")
	print("\n3 DESENCRIPTACIÓ")
	inp = str(input("\n>>> "))
	if inp not in ("1", "2", "3"):
		print("\nAcció '{}' no existeix".format(inp))
		continue
	elif inp == "1":
		p = generar_primer(2048)
		q = generar_primer(2048)
		N = p*q
		phi = (p-1)*(q-1)
		e = 3
		while mcd(phi, e) !=1:
			e += 2
		k = 1
		d = 1
		while not d == 0:        # Trobem el valor k
			k += 1
			d = (1+phi*k)%e
		d = (1+phi*k)//e         # Càlcul de d
		print("\nCLAU PRIVADA DE DESENCRIPTACIÓ: {}".format(d))
		print("\nCLAUS PÚBLIQUES: ")
		print("\nN = {}".format(N))
		print("\ne = {}".format(e))
		del inp, p, q, N, e, phi, d
		input()
		continue
	elif inp == "2":
		N = input("\nProporcioneu N: ")
		e = input("\nProporcioneu e: ")
		m = input("\nEl missatge (int): ")
		try:
			N, e, m = int(N), int(e), int(m)
		except ValueError:
			print("\nValor introduït no és enter.")
			continue
		c = pow(m, e, N)
		print("\nMISSATGE ENCRIPTAT: {}".format(c))
		del N, e, m, c
		input()
		continue
	elif inp == "3":
		N = input("\nProporcioneu N: ")
		d = input("\nProporcioneu la clau privada: ")
		c = input("\nMISSATGE ENCRIPTAT: ")
		try:
			N, d, c = int(N), int(d), int(c)
		except ValueError:
			print("\nValor introduït no és enter.")
			continue
		m = pow(c, d, N)
		print("\nMISSATGE DESENCRIPTAT: {}".format(m))
		del N, m, c, d
		input()
		continue
