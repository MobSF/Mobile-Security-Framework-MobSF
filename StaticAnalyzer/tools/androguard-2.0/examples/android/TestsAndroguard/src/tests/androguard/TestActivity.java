package tests.androguard;

import java.io.PrintStream;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

public class TestActivity<T> extends Activity {
	public int value;
	public int value2;
	private int test = 10;
	private static final int test2 = 20;
	public int test3 = 30;
	public int tab[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

	static {
		int t = 5;
		System.out.println("foobar");
	}

	public TestActivity() {
		value = 100;
		value2 = 200;
	}

	public TestActivity(int value, int value2) {
		this.value = value;
		this.value2 = value2;
	}

	public TestActivity(double value, double value2) {
		this.test = 5;
		this.value = (int) value;
		this.value2 = (int) value2;
	}

	public int test_base(int _value, int _value2) {
		int y = 0;
		double sd = -6;
		double zz = -5;
		double yy = -4;
		double xx = -3;
		double w = -2;
		double x = -1;
		double k = 0.0;
		double d = 1;
		double b = 2;
		double c = 3;
		double f = 4;
		double z = 5;
		double cd = 6;
		float g = 4.20f;

		double useless = g * c + b - y + d;

		System.out.println("VALUE = " + this.value + " VALUE 2 = "
				+ this.value2);

		for (int i = 0; i < (_value + _value2); i++) {
			y = this.value + y - this.value2;
			y = y & 200 * test1(20);

			y = this.value2 - y;
		}

		try {
			int[] t = new int[5];
			t[6] = 1;
		} catch (java.lang.ArrayIndexOutOfBoundsException e) {
			System.out.println("boom");
		}

		if (this.value > 0) {
			this.value2 = y;
		}

		switch (this.value) {
		case 0:
			this.value2 = this.pouet();
			break;
		default:
			this.value2 = this.pouet2();
		}

		switch (this.value) {
		case 1:
			this.value2 = this.pouet();
			break;
		case 2:
			this.value2 = this.pouet2();
			break;
		case 3:
			this.value2 = this.pouet3();
		}

		return y;
	}

	public int foo(int i, int j) {
		while (true) {
			try {
				while (i < j)
					i = j++ / i;
			} catch (RuntimeException re) {
				i = 10;
				continue;
			}
			if (i == 0)
				return j;
		}
	}

    public int foobis(int i, int j) {
		while (i < j && i != 10) {
			try {
					i = j++ / i;
			} catch (RuntimeException re) {
				i = 10;
				continue;
			}
		}
		return j;

    }

	public int foo2(int i, int j) {
		while (true) {
			if (i < j) {
				try {
					i = j++ / i;
				} catch (RuntimeException re) {
					i = 10;
					continue;
				}
			}
			if (i == 0)
				return j;
		}
	}

	public int foo4(int i, int j) {
		while (i < j) {
			try {
				i = j++ / i;
			} catch (RuntimeException re) {
				i = 10;
			}
		}
		return j;
	}

	public int test1(int val) {
		int a = 0x10;

		return val + a - 60 * this.value;
	}

	public int pouet() {
		int v = this.value;
		return v;
	}

	public void testVars(int z, char y) {
		int a = this.value * 2;
		int b = 3;
		int c = 4;
		int d = c + b * a - 1 / 3 * this.value;
		int e = c + b - a;
		int f = e + 2;
		int g = 3 * d - c + f - 8;
		int h = 10 + this.value + a + b + c + d + e + f + g;
		int i = 150 - 40 + 12;
		int j = h - i + g;
		int k = 10;
		int l = 5;
		int m = 2;
		int n = 10;
		int o = k * l + m - n * this.value + c / e - f * g + h - j;
		int p = a + b + c;
		int q = p - k + o - l;
		int r = a + b - c * d / e - f + g - h * i + j * k * l - m - n + o / p
				* q;
		System.out.println(" meh " + r);
		System.out.println(y);
		y += 'a';
		this.testVars(a, y);
		this.test1(10);
		pouet2();
		this.pouet2();
		int s = pouet2();
	}

	public static void testDouble() {
		double f = -5;
		double g = -4;
		double h = -3;
		double i = -2;
		double j = -1;
		double k = 0;
		double l = 1;
		double m = 2;
		double n = 3;
		double o = 4;
		double p = 5;

		long ff = -5;
		long gg = -4;
		long hh = -3;
		long ii = -2;
		long jj = -1;
		long kk = 0;
		long ll = 1;
		long mm = 2;
		long nn = 3;
		long oo = 4;
		long pp = 5;

		float fff = -5;
		float ggg = -4;
		float hhh = -3;
		float iii = -2;
		float jjj = -1;
		float kkk = 0;
		float lll = 1;
		float mmm = 2;
		float nnn = 3;
		float ooo = 4;
		float ppp = 5;

		double abc = 65534;
		double def = 65535;
		double ghi = 65536;
		double jkl = 65537;

		double mno = 32769;
		double pqr = 32768;
		double stu = 32767;
		double vwx = 32766;

		long aabc = 65534;
		long adef = 65535;
		long aghi = 65536;
		long ajkl = 65537;

		long amno = 32769;
		long apqr = 32768;
		long astu = 32767;
		long avwx = 32766;

		float babc = 65534;
		float bdef = 65535;
		float bghi = 65536;
		float bjkl = 65537;

		float bmno = 32769;
		float bpqr = 32768;
		float bstu = 32767;
		float bvwx = 32766;

		double abcd = 5346952;
		long dcba = 5346952;
		float cabd = 5346952;

		double zabc = 65534.50;
		double zdef = 65535.50;
		double zghi = 65536.50;
		double zjkl = 65537.50;

		double zmno = 32769.50;
		double zpqr = 32768.50;
		double zstu = 32767.50;
		double zvwx = 32766.50;

		float xabc = 65534.50f;
		float xdef = 65535.50f;
		float xghi = 65536.50f;
		float xjkl = 65537.50f;

		float xmno = 32769.50f;
		float xpqr = 32768.50f;
		float xstu = 32767.50f;
		float xvwx = 32766.50f;

		float ymno = -5f;
		float ypqr = -65535f;
		float ystu = -65536f;
		float yvwx = -123456789123456789.555555555f;
		double yvwx2 = -123456789123456789.555555555;
		int boom = -606384730;
		float reboom = -123456790519087104f;
		float gettype = boom + 2 + 3.5f;
		System.out.println(gettype);
	}

	public static void testCall1(float b) {
		System.out.println("k" + b);
	}

	public static void testCall2(long i) {
		new PrintStream(System.out).println("k" + i);
	}

	public static void testCalls(TestIfs d) {
		testCall2(3);
		TestIfs.testIF(5);
		System.out.println(d.getClass());
	}

	public static void testLoop(double a) {
		while (a < 10) {
			System.out.println(a);
			a *= 2;
		}
	}

	public void testVarArgs(int p, long[] p2, String... p3) {

	}
	
	public void testString( )
	{
		String a = "foo";
		String b = new String("bar");
		System.out.println(a + b);
	}

	public synchronized int pouet2() {
		int i = 0, j = 10;
		System.out.println("test");

		while (i < j) {
			try {
				i = j++ / i;
			} catch (RuntimeException re) {
				i = 10;
			}
		}
		this.value = i;
		return 90;
	}

	public int pouet3() {
		return 80;
	}

	public int go() {
		System.out.println(" test_base(500, 3) " + this.test_base(500, 3));
		return test + test2 + 10;
	}

	public void testAccessField() {
		TestArr$ays a = new TestArr$ays();
		a.d = new byte[5];
		a.d[2] = 'c';
		System.out.println("test :" + a.d[2]);
	}

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);
		
		Toast toast = Toast.makeText(getApplicationContext(), "this is a test ! " + 42, Toast.LENGTH_LONG);
		toast.show();
		/*
		TestLoops o = new TestLoops();
		o.testIrreducible(test3, test2);
		*/
	}
}
