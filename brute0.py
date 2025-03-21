import time
from Crypto.Random import get_random_bytes
from cryptogalyrex import galyrex

class BruteForceAttack:
    def __init__(self, galyrex_instance, ciphertext, expected_plaintext):
        self.galyrex_instance = galyrex_instance
        self.ciphertext = ciphertext
        self.expected_plaintext = expected_plaintext

    def attack(self):
        """
        Vykoná útok hrubou silou na šifrování GalyreX s 512bitovým klíčem. Tento útok bude prohledávat
        prostor všech možných klíčů. V reálných podmínkách se tento útok nedá realizovat na 512bitovém klíči
        kvůli velikosti prostoru (2^512). Tato implementace je připravena pro akademické testování.
        """
        print("Spouštím útok hrubou silou na 512bitový klíč...")
        start_time = time.time()

        # Brute-force útok na plný prostor klíčů, bez omezení (v akademických testech).
        i = 0
        while True:
            key = get_random_bytes(64)  # Generuje 512bitový klíč
            galyrex_copy = galyrex(key)

            try:
                decrypted_data = galyrex_copy.decrypt(self.ciphertext, b'fake_mac', b'fake_nonce')
                if decrypted_data == self.expected_plaintext:
                    print(f"Klíč nalezen po {i} pokusech!")
                    print(f"Doba útoku: {time.time() - start_time} sekund.")
                    return True
            except ValueError:
                pass  # Pokračujeme, pokud dešifrování selže

            i += 1  # Zvýšíme počet pokusů
            if i % 100000 == 0:  # Ukázkové informace o počtu pokusů
                print(f"Počet pokusů: {i}")

        print("Útok hrubou silou selhal.")
        print(f"Doba útoku: {time.time() - start_time} sekund.")
        return False
