/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package util;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import paillierp.key.PaillierPublicKey;
import ACNS.ZeroKnowledgeProofs.PublicParameters;


public class OtherUtil {
	
	

	public static BigInteger calculateMPrime(BigInteger n, byte[] message) {
		if (n.bitLength() > message.length * 8) {
			return new BigInteger(1, message);
		} else {
			int messageBitLength = message.length * 8;
			BigInteger trunc = new BigInteger(1, message);

			if (messageBitLength - n.bitLength() > 0) {
				trunc = trunc.shiftRight(messageBitLength - n.bitLength());
			}
			return trunc;
		}
	}
	

	
	
	public static byte[] sha256Hash(byte[]... inputs) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			for (byte[] input : inputs) {
				md.update(input);
			}
			return md.digest();

		} catch (NoSuchAlgorithmException ex) {
			throw new AssertionError();
		}
	}
	
	
	
	

	public static byte[] getBytes(ECPoint e) {
		byte[] x = e.getX().toBigInteger().toByteArray();
		byte[] y = e.getY().toBigInteger().toByteArray();
		byte[] output = new byte[x.length + y.length];
		System.arraycopy(x, 0, output, 0, x.length);
		System.arraycopy(y, 0, output, x.length, y.length);
		return output;
	}

	
	
	
	public static PublicParameters generatePublicParams(ECDomainParameters CURVE, int primeCertainty, int kPrime, SecureRandom rand, PaillierPublicKey paillierPubKey) {

		BigInteger p;
		BigInteger q;
		BigInteger pPrime;
		BigInteger qPrime;
		BigInteger pPrimeqPrime;
		BigInteger nHat;

		do {
			p = new BigInteger(kPrime / 2, primeCertainty, rand);
		} while (!p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
				.isProbablePrime(primeCertainty));

		pPrime = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

		do {
			q = new BigInteger(kPrime / 2, primeCertainty, rand);
		} while (!q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
				.isProbablePrime(primeCertainty));

		qPrime = q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));

		nHat = p.multiply(q);

		BigInteger h2 = RandomUtil.randomFromZnStar(nHat, rand);
		pPrimeqPrime = pPrime.multiply(qPrime);

		BigInteger x = RandomUtil.randomFromZn(pPrimeqPrime, rand);
		BigInteger h1 = h2.modPow(x, nHat);

		return new PublicParameters(CURVE, nHat, kPrime, h1, h2, paillierPubKey);

	}
	
}
