package tests.androguard;

public class TestIfs {
	private boolean P, Q, R, S, T;

	public static int testIF(int p) {
		int i;

		if (p > 0) {
			i = p * 2;
		} else {
			i = p + 2;
		}
		return i;
	}

	public static int testIF2(int p) {
		int i = 0;

		if (p > 0) {
			i = p * 2;
		} else {
			i = p + 2;
		}
		return i;
	}

	public static int testIF3(int p) {
		int i = 0;
		if (p > 0) {
			i = p * 2;
		}
		return i;
	}

	public static int testIF4(int p, int i) {
		if (p > 0 && p % 2 == 3) {
			i += p * 3;
		}
		return i;
	}
	
	public static int testIF5(int p, int i) {
		if ((p <= 0 && i == 0) || (p == i * 2 || i == p / 3)) {
			i = -p;
		}
		return i;
	}
	
	public static int testIfBool(int p, boolean b) {
		int i = 0;
		if ( p > 0 && b )
			i += p * 3;
		else if (b)
			i += 5;
		else
			i = 2;
		return i;
	}

	public static int testShortCircuit(int p) {
		int i = 0;
		if (p > 0 && p % 2 == 3) {
			i = p + 1;
		} else {
			i = -p;
		}
		return i;
	}

	public static int testShortCircuit2(int p) {
		int i = 0;
		if (p <= 0 || p % 2 != 3)
			i = -p;
		else
			i = p + 1;
		return i;
	}

	public static int testShortCircuit3(int p, int i) {
		if ((p <= 0 && i == 0) || (p == i * 2 || i == p / 3)) {
			i = -p;
		} else {
			i = p + 1;
		}
		return i;
	}

	public static int testShortCircuit4(int p, int i) {
		if ((p <= 0 || i == 0) && (p == i * 2 || i == p / 3))
			i = -p;
		else
			i = p + 1;
		return i;
	}

	public void testCFG() {
		int I = 1, J = 1, K = 1, L = 1;

		do {
			if (P) {
				J = I;
				if (Q)
					L = 2;
				else
					L = 3;
				K++;
			} else {
				K += 2;
			}
			System.out.println(I + "," + J + "," + K + "," + L);
			do {
				if (R)
					L += 4;
			} while (!S);
			I += 6;
		} while (!T);
	}

	public void testCFG2(int a, int b, int c) {
		a += 5;
		b += a * 5;
		if (a < b) {
			if (b < c) {
				System.out.println("foo");
			} else {
				System.out.println("bar");
			}
		}
		a = 10;
		while (a < c) {
			a += c;
			do {
				b = a++;
				System.out.println("baz");
			} while (c < b);
			b++;
		}
		System.out.println("foobar");
		if (a >= 5 || b * c <= c + 10) {
			System.out.println("a = " + 5);
		}
		System.out.println("end");
	}
}
