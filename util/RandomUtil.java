package util;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RandomUtil {
	
	
	//[0,n-1]
	public static BigInteger randomFromZn(BigInteger n, SecureRandom rnd) {
		BigInteger result;
		do {
			result = new BigInteger(n.bitLength(), rnd);
		} while (result.compareTo(n) != -1);
		
		return result;
	}
	
	
	//[1,n-1]中与n互素的数字
	public static BigInteger randomFromZnStar(BigInteger n, SecureRandom rnd) {
		BigInteger result;
		do {
			result = new BigInteger(n.bitLength(), rnd);
		} while (result.compareTo(n) != -1 || !result.gcd(n).equals(BigInteger.ONE));
		
		return result;
	}	
	


	public static boolean isElementOfZn(BigInteger element, BigInteger n) {
		return (element.compareTo(BigInteger.ZERO) != -1) && (element.compareTo(n) == -1);
	}
	

}
