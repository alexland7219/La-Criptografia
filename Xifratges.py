from string import ascii_uppercase as alph
import random
import matplotlib.pyplot as plt

# XIFRATGE D'ATBASH

def atbash_e(plaintext):
	plaintext = plaintext.upper()
	ciphertext = [alph[25-alph.index(c)] if c in alph else c for c in plaintext]
	return "".join(ciphertext)

def atbash_d(ciphertext):
	return atbash_e(ciphertext)


# XIFRATGE DE CÈSAR

def cesar_e(plaintext, shift):
	plaintext = plaintext.upper()
	ciphertext = [alph[(alph.index(c)+shift)%26] if c in alph else c for c in plaintext]
	return "".join(ciphertext)

def cesar_d(ciphertext, shift):
	ciphertext = ciphertext.upper()
	plaintext = [alph[(alph.index(c)-shift)%26] if c in alph else c for c in ciphertext]
	return "".join(plaintext)

# QUADRAT DE POLIBI

def matriu(keyword):
	matriu = [[0 for y in range(5)] for x in range(5)]
	i = j = 0
	for c in keyword.upper().replace("J", "I") + alph.replace("J", ""):
		if any([c in m for m in matriu]): continue
		matriu[i][j] = c
		j = (j+1)%5
		if j == 0: i += 1
	return matriu

def polibi_e(keyword, plaintext):
	M = matriu(keyword)
	ciphertext = ""
	for c in plaintext.upper().replace("J", "I"):
		if c not in alph:
			if c != " ": ciphertext += c + " "
			continue
		fila = [n for n in M if c in n][0]
		ciphertext += str(M.index(fila)+1) + str(fila.index(c)+1) + " "
	return ciphertext[:-1]

def polibi_d(keyword, ciphertext):
	M = matriu(keyword)
	plaintext = ""
	for n in ciphertext.split(" "):
		if len(n) != 2:
			plaintext += n + " "
			continue
		plaintext += M[int(n[0])-1][int(n[1])-1] + " "
	return plaintext[:-1]

# XIFRATGE AFÍ

def afi_e(a, b, plaintext):
	assert a in [2*x+1 for x in range(14) if (x%13)!=0]
	plaintext = plaintext.upper()
	ciphertext = [alph[(alph.index(c)*a+b)%26] if c in alph else c for c in plaintext]
	return "".join(ciphertext)

def afi_d(a, b, ciphertext):
	assert a in [2*x+1 for x in range(14) if (x%13)!=0]
	for i in range(1, 26):
		if (a*i)%26 == 1:
			a_inv = i
			break
	ciphertext = ciphertext.upper()
	plaintext = [alph[(a_inv*(alph.index(c)-b))%26] if c in alph else c for c in ciphertext]
	return "".join(plaintext)

# ANÀLISI DE LES FREQÜÈNCIES

def freq(text):
	d = {}
	for c in "".join(text.upper().split()):
		if c not in alph:
			continue
		d[c] = d.get(c, 0) + 1
	return d 


# ALGORISME D'EUCLIDES

def mcd(a, b):
	if b > a:
		return mcd(b, a)
	if a % b == 0:
		return b
	return mcd(b, a % b)

# XIFRATGE DE PLAYFAIR

def modif_miss(text):
	text = text.upper()
	text = "".join([c for c in text if c in alph])
	modf = text
	i = 0
	while i != len(modf):
		if modf[i] == modf[i-1] and i % 2 != 0:
			modf = modf[:i] + "X" + modf[i:]
			i += 1
		i += 1
	if len(modf) % 2 != 0:
		if modf[-1] == "X":
			modf += "Y"
		else:
			modf += "X"
	return modf

# Funció que afegeix X's quan calgui

def playfair_e(plaintext, keyword):
	M = matriu(keyword)  # Reutilitzant la funció de Polibi
	modf = modif_miss(plaintext)
	modf = [(modf[i:i+2]) for i in range(0, len(modf), 2)] 
	ciphertext = ""
	for p in modf:
		for r in M:
			if p[0] in r and p[1] in r: # Mateixa fila
				e = [r[(r.index(p[0])+1)%5], r[(r.index(p[1])+1)%5]]
				break
			elif p[0] in r:
				i = r.index(p[0])
				for s in M:             # Mateixa columna
					if p[1] in s and s.index(p[1]) == r.index(p[0]):
						e = [M[(M.index(r)+1)%5][i], M[(M.index(s)+1)%5][i]]
						break
					elif p[1] in s:     # Diferent Fila i Columna
						e = [r[s.index(p[1])], s[r.index(p[0])]]
						break
		ciphertext += "".join(e)
	return ciphertext

def playfair_d(ciphertext, keyword):
	M = matriu(keyword)
	modf = ciphertext
	modf = [(modf[i:i+2]) for i in range(0, len(modf), 2)] 
	plaintext = ""
	for p in modf:
		for r in M:
			if p[0] in r and p[1] in r: # Mateixa fila
				e = [r[(r.index(p[0])-1)%5], r[(r.index(p[1])-1)%5]]
				break
			elif p[0] in r:
				i = r.index(p[0])
				for s in M:             # Mateixa columna
					if p[1] in s and s.index(p[1]) == r.index(p[0]):
						e = [M[(M.index(r)-1)%5][i], M[(M.index(s)-1)%5][i]]
						break
					elif p[1] in s:     # Diferent Fila i Columna
						e = [r[s.index(p[1])], s[r.index(p[0])]]
						break
		plaintext += "".join(e)
	return plaintext

# XIFRATGE DE VIGENÈRE

def mapped_key(modal, key):
	assert all(i in alph for i in key)
	modal = modal.upper()
	map_key = []
	i = 0
	for c in modal:
		if c not in alph:
			map_key.append(c)
		else:
			map_key.append(key[i%len(key)])
			i += 1
	return map_key

def vigenere_e(plaintext, key):
	plaintext = plaintext.upper()
	key = mapped_key(plaintext, key.upper())
	ciphertext = [alph[(alph.index(a) + alph.index(b))%26] if a in alph else a for a, b in zip(plaintext, key)]
	return "".join(ciphertext)

def vigenere_d(ciphertext, key):
	ciphertext = ciphertext.upper()
	key = mapped_key(ciphertext, key.upper())
	plaintext = [alph[(alph.index(a)-alph.index(b))%26] if a in alph else a for a, b in zip(ciphertext, key)]
	return "".join(plaintext)

# BLOC D'UN SOL ÚS - OTP

def arr_dec(llarg):
	return [random.randint(1, 25) for _ in range(llarg)]

def otp_e(arr_dec, plaintext):
	plaintext = plaintext.upper()
	j = 0
	ciphertext = ""
	for i, c in enumerate(plaintext):
		if c not in alph:
			ciphertext += c
			j += 1
			continue
		ciphertext += alph[(arr_dec[i-j]+alph.index(c))%26]
	return "".join(ciphertext)

def otp_d(arr_dec, ciphertext):
	ciphertext = ciphertext.upper()
	j = 0
	plaintext = ""
	for i, c in enumerate(ciphertext):
		if c not in alph:
			plaintext += c
			j += 1
			continue
		plaintext += alph[(alph.index(c)-arr_dec[i-j])%26]
	return "".join(plaintext)

# MÀQUINA ENIGMA

RI = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
RII = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
RIII = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
UKW = "YRUHQSLDPXNGOKMIEBFZCWVJAT"

d = {"1":RI, "2":RII, "3":RIII}

def pas(rotors, osques, pos): 						 # Funció per a avançar una posició
	gir = False
	if pos[1] == osques[1]:                          # Si el segon rotor està en posició clau,
		rotors[0] = rotors[0][1:]+rotors[0][0]       # Moure el segon i el lent una posició
		pos[0] = alph[(alph.index(pos[0])+1)%26]
		rotors[1] = rotors[1][1:]+rotors[1][0]
		pos[1] = alph[(alph.index(pos[1])+1)%26]
		gir = True			                         # var que confirma que el segon ha avançat
	if pos[2] == osques[2] and not gir:	             # Si el primer està en posició clau,
		rotors[1] = rotors[1][1:]+rotors[1][0]		 # El segon avança si encara no ho ha fet
		pos[1] = alph[(alph.index(pos[1])+1)%26]	
	rotors[2] = rotors[2][1:]+rotors[2][0]			 # El primer rotor avança sempre
	pos[2] = alph[(alph.index(pos[2])+1)%26]
	return rotors, pos                             


def enigma(ordre_rotors, pos, osques, plaintext):   # MÀQUINA ENIGMA I
	plaintext = plaintext.upper() 					# plaintext en majúscules
	pos = list(pos)
	rotors = [d[ordre_rotors[0]], d[ordre_rotors[1]], d[ordre_rotors[2]]]  # Ordre dels rotors  
	for i in range(3):                                                     # Posicions inicials
		rotors[i] = rotors[i][alph.index(pos[i]):]+rotors[i][:alph.index(pos[i])]
	ciphertext = ""
	for c in plaintext:		                    # Si el caràcter no és una lletra,
		if c not in alph:
			ciphertext += c                     # ignora'l.
			continue
		rotors, pos = pas(rotors, osques, pos)  # Funció per a avançar una posició
		for i in [2, 1, 0]:                     # Anada de la senyal fins el reflector
			c = alph[(alph.index(rotors[i][alph.index(c)])-alph.index(pos[i]))%26]
		c = UKW[alph.index(c)] 					# Rebot del reflector UKW-B
		for i in range(3):                      # Tornada de la senyal al panell
			c = alph[rotors[i].index(alph[(alph.index(c)+alph.index(pos[i]))%26])]
		ciphertext += c                         # Recull de totes les lletres
	return ciphertext

# DATA ENCRYPTION STANDARD (DES)

IP = [58, 50, 42, 34, 26, 18, 10, 2, 
	  60, 52, 44, 36, 28, 20, 12, 4,
	  62, 54, 46, 38, 30, 22, 14, 6, 
	  64, 56, 48, 40, 32, 24, 16, 8,
	  57, 49, 41, 33, 25, 17, 9, 1, 
	  59, 51, 43, 35, 27, 19, 11, 3, 
	  61, 53, 45, 37, 29, 21, 13, 5, 
	  63, 55, 47, 39, 31, 23, 15, 7]

inv_IP = [40,   8,  48, 16, 56, 24, 64, 32, 
		  39,	7,	47,	15,	55,	23,	63,	31,
		  38,	6,	46,	14,	54,	22,	62,	30,
		  37,	5,	45,	13,	53,	21,	61,	29,
		  36,	4,	44,	12,	52,	20,	60,	28,
		  35,	3,	43,	11,	51,	19,	59,	27,
		  34,	2,	42,	10,	50,	18,	58,	26,
		  33,	1,	41,	9,	49,	17,	57,	25]


PC1e = [57,	49,	41,	33,	25,	17,	9, 
		1, 58, 50, 42, 34, 26, 18, 
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36]

PC1d = [63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14,	6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1,  5,
		3, 28, 15,  6,  21, 10,
		23,	19,	12,	4,	26,	8,
		16,	7,	27,	20, 13,	2,
		41,	52,	31,	37,	47,	55,
		30,	40,	51,	45,	33,	48,
		44,	49,	39,	56,	34,	53,
		46,	42,	50,	36,	29,	32]

EP = [32, 1, 2,	3,	4,	5,
	4,	5,	6,	7,	8,	9,
	8,	9,	10,	11,	12,	13,
	12,	13,	14,	15,	16,	17,
	16,	17,	18,	19,	20,	21,
	20,	21,	22,	23,	24,	25,
	24,	25,	26,	27,	28,	29,
	28,	29,	30,	31,	32,	1]

PF = [16, 7, 20, 21, 29, 12, 28, 17,
	 1,	15,	23,	26,	5,	18,	31,	10,
	 2,	8,	24,	14,	32,	27,	3,	9,
	 19, 13, 30, 6,	22,	11,	4,	25]


S1 = [[14,	4,	13,	1,	2,	15,	11,	8,	3,	10,	6,	12,	5,	9,	0,	7],
	  [0,	15,	7,	4,	14,	2,	13,	1,	10,	6,	12,	11,	9,	5,	3,	8],
	  [4,	1,	14,	8,	13,	6,	2,	11,	15,	12,	9,	7,	3,	10,	5,	0],
	  [15,	12,	8,	2,	4,	9,	1,	7,	5,	11,	3,	14,	10,	0,	6,	13]]

S2 = [[15,	1,	8,	14,	6,	11,	3,  4,	9,	7,	2,	13,	12,	0,	5,	10],
	  [3,	13,	4,	7,	15,	2,	8,	14,	12,	0,	1,	10,	6,	9,	11,	5],
	  [0,	14,	7,	11,	10,	4,	13,	1,	5,	8,	12,	6,  9,	3,	2,	15],
	  [13,	8,	10,	1,	3,	15,	4,	2,	11,	6,	7,	12,	0,	5,	14,	9]]

S3 = [[10,	0,	9,	14,	6,	3,	15,	5,	1,	13,	12,	7,	11,	4,	2,	8],
	  [13,	7,	0,	9,	3,	4,	6,	10,	2,	8,	5,	14,	12,	11,	15,	1],
	  [13,	6,	4,	9,	8,	15,	3,	0,	11,	1,	2,	12,	5,	10,	14,	7],
	  [1,	10,	13,	0,	6,	9,	8,	7,	4,	15,	14,	3,	11,	5,	2,	12]]

S4 = [[7,	13,	14,	3,	0,	6,	9,	10,	1,	2,	8,	5,	11,	12,	4,	15],
	  [13,	8,	11,	5,	6,	15,	0,	3,	4,	7,	2,	12,	1,	10,	14,	9],
	  [10,	6,	9,	0,	12,	11,	7,	13,	15,	1,	3,	14,	5,	2,	8,	4],
	  [3,	15,	0,	6,	10,	1,	13,	8,	9,	4,	5,	11,	12,	7,	2,	14]]

S5 = [[2,	12,	4,	1,	7,	10,	11,	6,	8,	5,	3,	15,	13,	0,	14,	9],
	  [14,	11,	2,	12,	4,	7,	13,	1,	5,	0,	15,	10,	3,	9,	8,	6],
	  [4,	2,	1,	11,	10,	13,	7,	8,	15,	9,	12,	5,	6,	3,	0,	14],
	  [11,	8,	12,	7,  1,	14,	2,	13,	6,	15,	0,	9,	10,	4,	5,	3]]

S6 = [[12,	1,	10,	15,	9,	2,	6,	8,	0,	13,	3,	4,	14,	7,	5,	11],
	  [10,	15,	4,	2,	7,	12,	9,	5,	6,	1,	13,	14,	0,	11,	3,	8],
	  [9,	14,	15,	5,	2,	8,	12,	3,	7,	0,	4,	10,	1,	13,	11,	6],
	  [4,	3,	2,	12,	9,	5,	15,	10,	11,	14,	1,	7,	6,	0,	8,	13]]

S7 = [[4,	11,	2,	14,	15,	0,	8,	13,	3,	12,	9,	7,	5,	10,	6,	1],
	  [13,	0,	11,	7,	4,	9,	1,	10,	14,	3,	5,	12,	2,	15,	8,	6],
	  [1,	4,	11,	13,	12,	3,	7,	14,	10,	15,	6,	8,	0,	5,	9,	2],
	  [6,	11,	13,	8,	1,	4,	10,	7,	9,	5,	0,	15,	14,	2,	3,	12]]

S8 = [[13,	2,	8,	4,	6,	15,	11,	1,	10,	9,	3,	14,	5,	0,	12,	7],
	  [1,	15,	13,	8,	10,	3,	7,	4,	12,	5,	6,	11,	0,	14,	9,	2],
	  [7,	11,	4,	1,	9,	12,	14,	2,	0,	6,	10,	13,	15,	3,	5,	8],
	  [2,	1,	14,	7,	4,	10,	8,	13,	15,	12,	9,	0,	3,	5,	6,	11]]

S_BOX = [S1, S2, S3, S4, S5, S6, S7, S8]

def xor(a, b):
	return [str(int(x==y)) for x, y in zip(a, b)]

def LCS(a, ronda):
	if ronda in (1, 2, 9, 16):
		n = 1
	else:
		n = 2
	return a[n:]+a[:n]

def dec_a_bin(n):
	# Decimal de l'1 al 16
	b = bin(n)[2:]
	return (4-len(b))*"0"+b

def DES(plaintext, clau):
	plaintext = [plaintext[x-1] for x in IP]                     # Permutació Inicial (IP)
	E = plaintext[:len(plaintext)//2]
	D = plaintext[len(plaintext)//2:]                            # Dividir en esq. i dreta
	Ek = [key[x-1] for x in PC1e]                                # Permuted Choice 1 (PC-1)
	Dk = [key[x-1] for x in PC1d] 
	for r in range(1, 17):                                       # Iterem amb 'r' (la ronda)
		Ek = LCS(Ek, r)
		Dk = LCS(Ek, r)
		c = [D[x-1] for x in EP]                                 # Permutació d'Expansió (EP)
		c = xor(c, [list(Ek+Dk)[x-1] for x in PC2])				 # Permuted Choice 2 i XOR
		s = []                                                      
		for i in range(0, len(c), 6):                            # S-BOX
			t = c[i:(i+6)]
			fila = int(t[0]+t[-1], 2)
			col  = int("".join(t[1:5]), 2)
			t = dec_a_bin(S_BOX[i//6][fila][col])
			s += t
		s = [s[x-1] for x in PF]								 # Permutació (PF)
		E, D = D, xor(s, E)
	ciphertext = D + E                                           # 32 Bit Swap
	return "".join([ciphertext[x-1] for x in inv_IP])            # Permutació Inicial Inversa

# INTERCANVI DE CLAUS DIFFIE-HELLMAN

def diffie_hellman(g, p, clau_a, clau_b): 
	"""
	On 'g' és el generador, 'p' el nombre primer,
	'clau_a' la clau privada de l'Alice i
	'clau_b' la clau privada d'en Bob.
	"""
	a = pow(g, clau_a, p)
	b = pow(g, clau_b, p)
	print("L'Alice envia a en Bob el valor {}".format(str(a)))
	print("En Bob envia a l'Alice el valor {}".format(str(b)))
	r1 = pow(b, clau_a, p)
	r2 = pow(a, clau_b, p)
	print("\nL'Alice i en Bob obtenen el valor {}".format(str(r1)))
	if r1 == r2:
		print("\nINTERCANVI DIFFIE-HELLMAN AMB ÈXIT")
	else:
		print("\nERROR EN L'INTERCANVI DIFFIE-HELLMAN")

# FUNCIÓ PHI D'EULER

def phi(n):
	# FUNCIÓ PHI D'EULER
	return len([x for x in range(1, n+1) if mcd(x, n) == 1])

def grafic_phi(n):
	# import matplotlib.pyplot as plt
	# GRÀFICA DE LA FUNCIÓ PHI AMB LA LLIBRERIA MATPLOTLIB.PYPLOT
	x = [i for i in range(1, n)]
	y = [phi(i) for i in x]
	plt.scatter(x, y, color="indigo", s=3)
	plt.xlabel("x")
	plt.ylabel("ϕ(x)")
	plt.title("Funció ϕ d'Euler")
	plt.show()

# TEST DE PRIMALITAT DE FERMAT

def fermat(p, tests = 100):
	if (p % 2 == 0 and p != 2) or p < 2:
		return False
	if p == 2:
		return True
	for _ in range(tests):
		a = random.randint(2, p-1)
		if p % a == 0:
			return False
		else:
			if pow(a, p-1, p) == 1:
				continue
			else:
				return False
	return True

def generar_primer(llargada=1024): # Nombre de bits
	p = 0
	while not fermat(p):
		p = random.getrandbits(llargada)
	return p

# RSA

def generar_claus(llarg=1024): # Nombre de bits
	p = generar_primer(llarg)  # Generació primers
	q = generar_primer(llarg)
	N = p * q       
	phi = (p-1)*(q-1)
	e = 3 
	while mcd(phi, e) != 1:  # MCD amb Algor. Euclides
		e += 2
	k = 1
	d = 1
	while not d == 0:        # Trobem el valor k
		k += 1
		d = (1+phi*k)%e
	d = (1+phi*k)//e         # Càlcul de d
	print("\nMÒDUL PÚBLIC N:\n"+str(N))
	print("\nCLAU PÚBLICA D'ENCRIPTACIÓ e: "+str(e))
	print("\nCLAU PRIVADA DE DESENCRIPTACIÓ d:\n"+str(d))

def rsa_e(m, e, N):
	return pow(m, e, N)   # Exponenciació Modular

def rsa_d(c, d, N):
	return pow(c, d, N)   # Exponenciació Modular
