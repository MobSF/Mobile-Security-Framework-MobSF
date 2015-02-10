package tests.androguard;


public class TestInvoke {
	
    public TestInvoke( ) {
      TestInvoke1(42 );
    }

    public int TestInvoke1( int a )
    {
      return TestInvoke2( a, 42 );
    }    
    
    public int TestInvoke2( int a, int b )
    {
      return TestInvoke3( a, b, 42 );
    }    

    public int TestInvoke3( int a, int b, int c )
    {
      return TestInvoke4( a, b, c, 42 );
    }    
    
    public int TestInvoke4( int a, int b, int c, int d )
    {
      return TestInvoke5( a, b, c, d, 42 );
    }    
    
    public int TestInvoke5(int a, int b, int c, int d, int e)
    {
      return TestInvoke6( a, b, c, d, e, 42 );
    }    
    
    public int TestInvoke6( int a, int b, int c, int d, int e, int f )
    {
      return TestInvoke7( a, b, c, d, e, f, 42);
    }    
    
    public int TestInvoke7( int a, int b, int c, int d, int e, int f, int g )
    {
      return TestInvoke8( a, b, c, d, e, f, g, 42);
    }    
    
    public int TestInvoke8( int a, int b, int c, int d, int e, int f, int g, int h )
    {
      return a * b * c * d * e *f * g *h;
    }    

}
