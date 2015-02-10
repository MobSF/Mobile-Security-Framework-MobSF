package tests.androguard;

public class TestSynthetic {
	
	public static void TestSynthetic1( ){
		final Object o = new Object();

		new Thread(){
			public void run(){
				System.out.println( "o : " + o.hashCode() );
			}
		}.start();
	}

	public static void TestSynthetic2() {
		System.out.println( "o : " + 
			new Object(){
				public int toto(char c){
					return Integer.parseInt("" + c);
				}
			}.toto('k')
		);
	}
	
	public static void TestSynthetic3( ){
		Integer o = new Integer(5);

		new Thread(){
			Integer o = this.o;
			public void run(){
				System.out.println( "o : " + o.hashCode() );
			}
		}.start();
	}
	
	public static void TestSynthetic4( final int t ) {
		final Object o = new Object();
		
		new Thread(){
			public void run(){
				synchronized(o){
					if ( t == 0 ) {
						TestSynthetic1();
					}
					else {
						TestSynthetic2();
					}
				}
			}
		}.start();
		
		System.out.println("end");
	}

	
	public class Bridge<T> {
		public T getT(T arg){
			return arg;
		}
	}
	
	public class BridgeExt extends Bridge<String>{
		public String getT(String arg){
			return arg;
		}
	}
	
	public static void TestBridge( ){
		TestSynthetic p = new TestSynthetic();
		TestSynthetic.Bridge<Integer> x = p.new Bridge<Integer>();
		System.out.println("bridge<integer> " + x.getT(5));
		TestSynthetic.Bridge<String> w = p.new BridgeExt();
		System.out.println("bridgeext " + w.getT("toto"));	
	}

}
