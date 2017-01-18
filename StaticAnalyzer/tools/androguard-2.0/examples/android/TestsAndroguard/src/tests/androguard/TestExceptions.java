package tests.androguard;

public class TestExceptions {
	
	public int testException1( int a )
	{
		try {
			a = 5 / 0;
		} catch ( ArithmeticException e ) {
			a = 3;
		}
		return a;
	}
	
	public static int testException2( int a, int b ) throws ArrayIndexOutOfBoundsException
	{
		int [] t = new int[b];
		
		if ( b == 10 )
			b++;
		
		for( int i = 0; i < b; i++ )
		{
			t[i] = 5;
		}
		
		return a + t[0];
	}
	
	public int testException3( int a, int[] t )
	{
		int result = 0;
		
		if ( a % 2 == 0 )
		{
			try {
				result = t[a];
			} catch (ArrayIndexOutOfBoundsException e) {
				result = 1337;
			}
		}
		else if ( a % 3 == 0 ) {
			result = a * 2;
		} else {
			result = t[0] - 10;
		}
		
		return result;
	}
	
	public int testException4( int a ) 
	{
		int res = 15;
		
		res += a;
		
		try {
			Runtime b = Runtime.getRuntime();
			b.notifyAll();
		} catch( RuntimeException e ) {
			System.out.println("runtime " + e.getMessage());
		}
		
		try {
			Runtime c = Runtime.getRuntime();
			c.wait();
		}
		catch (RuntimeException e) {
			System.out.println("runtime " + e.getMessage());
		}
		catch (Exception e) {
			System.out.println("exception e " + e.getMessage());
		}
		
		try {
			res /= a;
		} catch (Exception e) {	
			System.out.println("exception e " + e.getMessage());
		}
		
		System.out.println("end");
		return res;
		
	}
	
	public static void testTry1(int b)
	{
		int a = 15;
		try {
			if ( b % 2 == 0)
			{
				a = a / b;
				if ( a - 3 == 4 )
					System.out.println("lll");
			}
			else {
				a = a * b;
				System.out.println("ppp");
			}
		} catch(ArithmeticException e){
			System.out.println("oupla");
		}
	}
	
	public static void testCatch1(int b)
	{
		int a = 15;
		try {
			if ( b % 2 == 0 )
			{
				a = a / b;
				if ( a - 3 == 4 )
					System.out.println("mmm");
			} else {
				a = a * b;
				System.out.println("qqq");
			}
		} catch(ArithmeticException e)
		{
			if ( a == 12 )
				System.out.println("test");
			else {
				b += 3 * a;
				System.out.println("test2 " + b);
			}
		}
	}
	
	public static void testExceptions( String [] z )
	{
		System.out.println( "Result test1 : " + new TestExceptions().testException1( 10 ) );
		
		System.out.println( "=================================" );
		try {
			System.out.println( "Result test2 : " + testException2( 5, 10 ) );
		} catch (ArrayIndexOutOfBoundsException e) {
			System.out.println( "Result test2 : " + testException2( 5, 9 ) );
		}
		
		System.out.println( "=================================" );
		int [] t = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
		System.out.println( "Result test3 : " + new TestExceptions().testException3( 8, t ) );
		System.out.println( "Result test3 : " + new TestExceptions().testException3( 9, t ) );
		System.out.println( "Result test3 : " + new TestExceptions().testException3( 7, t ) );
	}
}