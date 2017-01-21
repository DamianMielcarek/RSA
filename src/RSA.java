import javax.swing.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	private BigInteger n, d, e;

	private int bitlen = 1024;

	// Tworzenie instancji, która może zarówno szyfrować, jak i deszyfrować za pomocą czyjegoś klucza publicznego.
	public RSA(BigInteger newn, BigInteger newe) {
		n = newn;
		e = newe;
	}

	// Tworzenie instancji, która może zarówno szyfrować, jak i deszyfrować.
	public RSA(int bits) {
		bitlen = bits;
		SecureRandom r = new SecureRandom();
		BigInteger p = new BigInteger(bitlen / 2, 100, r);
		BigInteger q = new BigInteger(bitlen / 2, 100, r);
		n = p.multiply(q);
		BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
				.subtract(BigInteger.ONE));
		e = new BigInteger("3");
		while (m.gcd(e).intValue() > 1) {
			e = e.add(new BigInteger("2"));
		}
		d = e.modInverse(m);
	}

	// Szyfrowanie podanej wiadomości.
	public synchronized String encrypt(String message) {
		return (new BigInteger(message.getBytes())).modPow(e, n).toString();
	}

	// Szyfrowanie podanej wiadomości.
	public synchronized BigInteger encrypt(BigInteger message) {
		return message.modPow(e, n);
	}

	// Odszyfrowywanie szyfrogramu wiadomości.
	public synchronized String decrypt(String message) {
		return new String((new BigInteger(message)).modPow(d, n).toByteArray());
	}

	// Odszyfrowywanie szyfrogramu wiadomości.
	public synchronized BigInteger decrypt(BigInteger message) {
		return message.modPow(d, n);
	}

	// Generowanie nowego zestawu kluczy publicznych i prywatnych.
	public synchronized void generateKeys() {
		SecureRandom r = new SecureRandom();
		BigInteger p = new BigInteger(bitlen / 2, 100, r);
		BigInteger q = new BigInteger(bitlen / 2, 100, r);
		n = p.multiply(q);
		BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
				.subtract(BigInteger.ONE));
		e = new BigInteger("3");
		while (m.gcd(e).intValue() > 1) {
			e = e.add(new BigInteger("2"));
		}
		d = e.modInverse(m);
	}

	// Zwracanie modułu.
	public synchronized BigInteger getN() {
		return n;
	}

	// Zwracanie klucza publicznego.
	public synchronized BigInteger getE() {
		return e;
	}

	public static void main(String[] args) {
		RSA rsa = new RSA(1024);

		String text1 = JOptionPane.showInputDialog(null, "Podaj wiadomość do zaszyfrowania");
		BigInteger plaintext = new BigInteger(text1.getBytes());

		BigInteger ciphertext = rsa.encrypt(plaintext);
		JOptionPane.showMessageDialog(null, "Szyfrogram: " + ciphertext);
		plaintext = rsa.decrypt(ciphertext);

		String text2 = new String(plaintext.toByteArray());
		JOptionPane.showMessageDialog(null, "Wiadomość odszyfrowana: " + text2);
	}
}