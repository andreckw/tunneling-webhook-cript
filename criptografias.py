from random import randint, choice
from math import gcd

class SHA256():
    
    bits512 = ""
    Hs = []
    K = []
    texto_criptografado = ""
    
    def __init__(self, texto) -> None:
        # Transforma em ASCII
        ascii = self._trasformar_em_ascci(texto)
        
        # Transforma o ASCII em bits
        bits448 = ""
        for a in ascii:
            bits448 += format(a, '08b')
        
        tamanho_mensagem_original = len(bits448)
        
        # Faz o padding de 1 e 0 até o 448
        bits448 += "1"
        
        while len(bits448) % 512 != 448:
            bits448 += "0"
                
        # Transforma o tamanho em bits
        bits64 = format(tamanho_mensagem_original, '064b')
                
        self.bits512 = f"{bits448}{bits64}"
        self._inicializar_registrador()
    
    
    def _inicializar_registrador(self):
        self.Hs = []
        hexa_primos = ["0x6a09e667", "0xbb67ae85", "0x3c6ef372", "0xa54ff53a", "0x510e527f", "0x9b05688c", "0x1f83d9ab", "0x5be0cd19"]
        
        for n in hexa_primos:
            aux = bin(int(n[2:],16))[2:]
            while len(aux) < 32:
                aux = "0" + aux
            self.Hs.append(aux)
            

    
    
    def criptografar(self):
        
        for k in range(0, len(self.bits512), 512):
            W = []
            chunck = self.bits512[k:k+512]
        
            for j in range(0, 512, 32):
                W.append(chunck[j:(j+32)])
        
            i = 0
            while len(W) < 64:
                w0 = W[i]
                w1 = W[i+1]
                w9 = W[i+9]
                w14 = W[i+14]
                
                rot1 = self.rotacionar_deslocar(w1, [7, 18], [3])
                rot2 = self.rotacionar_deslocar(w14, [17, 19], [10])

                
                new_w1 = ""
                new_w14 = ""
                for j in range(0, 32):
                    if (rot1[0][j] == "1") ^ (rot1[1][j] == "1") ^ (rot1[2][j] == "1"):
                        new_b1 = "1"
                    else:
                        new_b1 = "0"
                    
                    if (rot2[0][j] == "1") ^ (rot2[1][j] == "1") ^ (rot2[2][j] == "1"):
                        new_b2 = "1"
                    else:
                        new_b2 = "0"
                    
                    new_w1 += new_b1
                    new_w14 += new_b2
                
                new_w = int(w0, 2) + int(new_w1, 2) + int(w9, 2) + int(new_w14, 2)
                new_w = format(new_w, "08b")
                
                if (len(new_w) > 32):
                    new_w = int(new_w, 2) % (2**32)
                    new_w = format(new_w, "08b")
                    
                while (len(new_w) < 32):
                    new_w = "0" + new_w
                
                W.append(new_w)
                i += 1
            self._inicializar_k()
            self.compressao(W)
        
        return self.texto_criptografado
        
        
    def compressao(self, W):
        a, b, c, d, e, f, g, h = self.Hs
        
        for i in range(64):
            
            aux = self.rotacionar_deslocar(e, [6,11,25])
            aux1 = self.rotacionar_deslocar(a, [2,13,22])
            S1 = ""
            S0 = ""
            ch = ""
            maj = ""
            for j in range(0, 32):

                if (aux[0][j] == "1") ^ (aux[1][j] == "1") ^ (aux[2][j] == "1"):
                    S1 += "1"
                else:
                    S1 += "0"

                if (aux1[0][j] == "1") ^ (aux1[1][j] == "1") ^ (aux1[2][j] == "1"):
                    S0 += "1"
                else:
                    S0 += "0"

                if (e[j] == "1" and f[j] == "1") ^ ((not e[j] == "1") and g[j] == "1"):
                    ch += "1"
                else:
                    ch += "0"

                if (a[j] == "1" and b[j] == "1") ^ (a[j] == "1" and c[j] == "1") ^ (b[j] == "1" and c[j] == "1"):
                    maj += "1"
                else:
                    maj += "0"
                
            t1 = bin(int(h, 2) + int(S1, 2) + int(ch, 2) + int(self.K[i], 2) + int(W[i], 2))[2:]
            if len(t1) > 32:
                t1 = int(t1, 2) % (2**32)
                t1 = bin(t1)[2:]
            while len(t1) < 32:
                t1 = "0" + t1

            t2 = bin(int(S0, 2) + int(maj, 2))[2:]
            if len(t2) > 32:
                t2 = int(t2, 2) % (2**32)
                t2 = bin(t2)[2:]
            while len(t2) < 32:
                t2 = "0" + t2


            h = g
            g = f
            f = e
            e = bin(int(d, 2) + int(t1, 2))[2:]
            
            if len(e) > 32:
                e = int(e, 2) % (2**32)
                e = bin(e)[2:]
            while len(e) < 32:
                e = "0" + e

            d = c
            c = b
            b = a
            a = bin(int(t1, 2) + int(t2, 2))[2:]

            if len(a) > 32:
                a = int(a, 2) % (2**32)
                a = bin(a)[2:]
            while len(a) < 32:
                a = "0" + a

        self.Hs[0] = self._converter_para_32bits(bin(int(a, 2) + int(self.Hs[0], 2))[2:])
        self.Hs[1] = self._converter_para_32bits(bin(int(b, 2) + int(self.Hs[1], 2))[2:])
        self.Hs[2] = self._converter_para_32bits(bin(int(c, 2) + int(self.Hs[2], 2))[2:])
        self.Hs[3] = self._converter_para_32bits(bin(int(d, 2) + int(self.Hs[3], 2))[2:])
        self.Hs[4] = self._converter_para_32bits(bin(int(e, 2) + int(self.Hs[4], 2))[2:])
        self.Hs[5] = self._converter_para_32bits(bin(int(f, 2) + int(self.Hs[5], 2))[2:])
        self.Hs[6] = self._converter_para_32bits(bin(int(g, 2) + int(self.Hs[6], 2))[2:])
        self.Hs[7] = self._converter_para_32bits(bin(int(h, 2) + int(self.Hs[7], 2))[2:])

        h_concatenado = "".join(self.Hs)

        self.texto_criptografado = format(int(h_concatenado, 2), "064x")
                
        
        
        
    def rotacionar_deslocar(self, bits, rotates = [], descolocacoes = []):
        retorno = []
        
        for r in rotates:
            retorno.append(bits[len(bits) - r:] + bits[:-r])
        
        for d in descolocacoes:
            retorno.append("0"*d + bits[:-d])
        
        return retorno

    def _converter_para_32bits(self, binarios):
        if len(binarios) > 32:
            binarios = int(binarios, 2) % (2**32)
            binarios = bin(binarios)[2:]
        
        while len(binarios) < 32:
            binarios = "0"+binarios
        
        return binarios
        
    def _inicializar_k(self):
        primos_64 = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
            59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
            137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
            227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311
        ]
        
        for p in primos_64:
            fracionaria = (p ** (1/3)) % 1
            bits = format(int(fracionaria * (2**32)), "08b")
            while (len(bits) < 32):
                bits = "0" + bits
            self.K.append(bits)
    
    
    def _trasformar_em_ascci(self, texto):
        if (type(texto) == bytes):
            return bytearray(texto)

        return bytearray(texto, encoding="utf-8")


class RSA():
    
    p = 0
    q = 0
    totiente_n = 0
    n = 0
    e = 2
    d = 2
    texto_criptografado = False
    
    
    def criar_chaves(self, testar = False):
        if not testar:
            primos = self._gerarprimos()
            self.p = choice(primos)
            while not self._isprimo(self.p):
                self.p = choice(primos)
            
            self.q = choice(primos)
            while not self._isprimo(self.q) and self.q == self.p:
                self.q = choice(primos)
        
        else:
            self.p = 17
            self.q = 23
        
        
        self.totiente_n = (self.p - 1) * (self.q - 1)
        self.n = self.p * self.q
        
        while 1 < gcd(self.e, self.totiente_n) and self.e < self.totiente_n:
            self.e += 1
        
        while ((self.d * self.e) % self.totiente_n != 1) and self.d < self.totiente_n:
            self.d += 1

    
    def criptografar(self, texto, chave):
        chaves = chave.split(",")
        
        self.e = int(chaves[0])
        self.n = int(chaves[1])
        
        ascii = self._transformar_em_ascii(texto)
        retorno = ""
        
        for m in ascii:
            retorno += f"{(m ** self.e) % self.n},"
        
        retorno = retorno[:len(retorno) - 1]
        
        self.texto_criptografado = retorno
        
        return retorno
    
    
    def descriptografar(self, texto):
        
        with open("chave_privada.txt") as f:
            chave = f.read()
            chaves = chave.split(",")
            d = int(chaves[0])
            n = int(chaves[1])
        
        texto = texto.split(",")
        
        
        texto_descript = ""
        i = 0
        for t in texto:
            print(f"descriptografando: {i/len(texto)*100}%", end="\r")
            m = (int(t) ** d) % n
            texto_descript += chr(m)
            i+=1
        print()
                
        return texto_descript
        
                
    
    
    def _transformar_em_ascii(self, texto):
        texto_bytes = ""
        if (type(texto) == bytes):
            texto_bytes = bytearray(texto)
        else:
            texto_bytes = bytearray(texto, encoding="utf-8")
        
        retorno = []
        for a in texto_bytes:
            retorno.append(int(a))
        
        return retorno
            
        
    
    def _gerarprimos(self):
        x = 2
        y = randint(2, 10**4)
        retorno = []
        
        for i in range(x-1, y):
            print(f"Gerando primos {i/y*100}%", end="\r")
            if self._isprimo(i):
                retorno.append(i)
        print()
        return retorno
    
    
    def _isprimo(self, num):
        retorno = True
        for divisor in range(1, num):
            if num % divisor == 0 and divisor != 1:
                retorno = False
                break
        
        return retorno



class Base64():

    _elementos = []

    def __init__(self):
        self._carregar_elementos()


    def criptografar(self, texto):
        ascci = self._trasformar_em_ascci(texto)
        
        bits = ""
        for a in ascci:
            bits += format(a, "08b")
        
        padding = 0
        while len(bits) % 6 != 0:
            bits += "0"*8
            padding += 1        
        
        texto = ""
        for i in range(0, len(bits), 6):
            elem = bits[i:i+6]
            texto += self._elementos[int(elem, 2)]
        
            
        texto = texto[0:len(texto) - padding] + "="*padding
        
        return texto


    def descriptografar(self, texto):
        padding = len(texto.split("=")) - 1
        
        texto = texto.replace("=", "")
        
        self._elementos = {valor: chave for chave, valor in self._elementos.items()}
        bits = ""
        for i in texto:
            elem = self._elementos[i]
            bits += format(elem, "06b")
        
        bits = bits + "000000"*padding
        print(bits)
        
        texto = bytearray()
        for i in range(0, len(bits), 8):
            texto.append(int(bits[i:i+8], 2))
                
        return texto.decode("utf-8")

    def _trasformar_em_ascci(self, texto):
        if (type(texto) == bytes):
            return bytearray(texto)

        return bytearray(texto, encoding="utf-8")

    
    def _carregar_elementos(self):
        self._elementos = {
            0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E', 5: 'F', 6: 'G', 7: 'H', 8: 'I', 9: 'J',
            10: 'K', 11: 'L', 12: 'M', 13: 'N', 14: 'O', 15: 'P', 16: 'Q', 17: 'R', 18: 'S', 19: 'T',
            20: 'U', 21: 'V', 22: 'W', 23: 'X', 24: 'Y', 25: 'Z', 26: 'a', 27: 'b', 28: 'c', 29: 'd',
            30: 'e', 31: 'f', 32: 'g', 33: 'h', 34: 'i', 35: 'j', 36: 'k', 37: 'l', 38: 'm', 39: 'n',
            40: 'o', 41: 'p', 42: 'q', 43: 'r', 44: 's', 45: 't', 46: 'u', 47: 'v', 48: 'w', 49: 'x',
            50: 'y', 51: 'z', 52: '0', 53: '1', 54: '2', 55: '3', 56: '4', 57: '5', 58: '6', 59: '7',
            60: '8', 61: '9', 62: '+', 63: '/'
        }
        