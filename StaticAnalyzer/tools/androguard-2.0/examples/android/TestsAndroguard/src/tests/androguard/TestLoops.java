package tests.androguard;

import android.content.pm.LabeledIntent;
import android.util.Log;

public class TestLoops {

	protected static class Loop {
		public static int i;
		public static int j;
	}

	public void testWhile() {
		int i = 5, j = 10;
		while (i < j) {
			j += i / 2.0 + j;
			i += i * 2;
		}
		Loop.i = i;
		Loop.j = j;
	}

    public void testWhile2() {
        while(true)
            System.out.println("toto");
    }

    public void testWhile3(int i, int j)
    {
        while ( i < j && i % 2 == 0 )
        {
            i += j / 3;
        }
    }

    public void testWhile4(int i, int j)
    {
        while ( i < j || i % 2 == 0 )
        {
            i += j / 3;
        }
    }
    
    public void testWhile5(int i, int j, int k )
    {
    	while ( ( i < j || i % 2 == 0 ) && ( j < k || k % 2 == 0) )
    		i += k - j;
    }

	public void testFor() {
		int i, j;
		for (i = 5, j = 10; i < j; i += i * 2) {
			j += i / 2.0 + j;
		}
		Loop.i = i;
		Loop.j = j;
	}

	public void testDoWhile() {
		int i = 5, j = 10;
		do {
			j += i / 2.0 + j;
			i += i * 2;
		} while (i < j);
		Loop.i = i;
		Loop.j = j;
	}

	public int testNestedLoops(int a) {
		if (a > 1000) {
			return testNestedLoops(a / 2);
		} else {
			while (a > 0) {
				a += 1;
				while (a % 2 == 0) {
					a *= 2;
					while (a % 3 == 0) {
						a -= 3;
					}
				}
			}
		}
		return a;
	}

	public void testMultipleLoops() {
		int a = 0;
		while (a < 50)
			a += 2;
		while (a % 3 == 0)
			a *= 5;
		while (a < 789 && a > 901)
			System.out.println("woo");
	}

	public int testDoWhileTrue(int n) {
		do {
			n--;
			if (n == 2)
				return 5;
			if (n < 2)
				n = 500;
		} while (true);
	}

	public int testWhileTrue(int n) {
		while (true) {
			n--;
			if (n == 2)
				return 5;
			if (n < 2)
				n = 500;
		}
	}

	public int testDiffWhileDoWhile(int n) {
		while (n != 2) {
			if (n < 2)
				n = 500;
		}
		return 5;
	}

	public void testReducible(boolean x, boolean y) {
		int a = 0, b = 0;
		if (x)
			while (y) {
				a = b + 1;
				b++;
			}
		else
			while (y) {
				b++;
				a = b + 1;
			}
		Loop.i = a;
		Loop.j = b;
	}

	public void testIrreducible(int a, int b) {
		while (true) {
			if (b < a) {
				Log.i("test", "In BasicBlock A");
			}
			b = a - 1;
			Log.i("test2", "In BasicBlock B");
		}
	}
	
	public int testBreak( boolean b ) {
		int a = 0, c = 0;
		while(true) {
			System.out.println("foo");
			a += c;
			c += 5;
			if ( a == 50 )
				b = true;
			if ( b )
				break;
		}
		return a + c;
	}

    public int testBreakbis( boolean b ) {
        int a = 0, c = 0;
        do {
            System.out.println("foo");
            a += c;
            c += 5;
            if ( a == 50 )
                b = true;
            if ( b )
                break;
        } while(true);
        return a + c;
    }
	
    public int testBreakMid( boolean b ) {
    	int a = Loop.i, c = Loop.j;
    	while(true) {
    		System.out.println("foo");
    		a += c;
    		c += 5;
    		if ( a == 50 )
    			b = !b;
    		if ( b ) break;
    		System.out.println("bar");
    		a *= 2;
    	}
    	return a + c;
    }
    
	public int testBreakDoWhile( boolean b ) {
		int a = 0, c = 0;
		do {
			System.out.println("foo");
			a += c;
			c += 5;
			if ( a == 50 )
				b = true;
		}while ( b );
		return a + c;
	}
	
	public int testBreak2( boolean b ) {
		int a = 0, c = 0;
		while (true) {
			System.out.println("foo");
			a += c;
			c += 5;
			if ( a == 50 && b )
				break;
		}
		return a + c;
	}
	
	public void testBreak3( boolean b ) {
		int a = 0, c = 0;
		while ( true ){
			System.out.println("foo");
			a += c;
			c += 5;
			if ( a == 50 && b )
				break;
		}
	}
	
	public void testBreak4( boolean b, int d ) {
		int a = 0, c = 0;
		while ( c < 50 ) {
			System.out.println("foo");
			a += c;
			c +=5;
			if ( a == d )
				break;
		}
	}
}
