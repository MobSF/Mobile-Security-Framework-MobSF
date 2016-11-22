import java.util.ArrayList;
import java.util.List;


public class TestDefaultPackage {

	static long [] test_;
	private class TestInnerClass {
		private int a, b;

		private TestInnerClass(int a, int b)
		{
			this.a = a;
			this.b = b;
		}
		
		public void Test(int d)
		{
			System.out.println("Test2: " + this.a + d + this.b);
		}

		private class TestInnerInnerClass {
			private int a, c;
			
			private TestInnerInnerClass(int a, int c)
			{
				this.a = a;
				this.c = c;
			}
			
			public void Test(int b)
			{
				System.out.println("Test: " + this.a * b + this.c);
			}
		}
	}
	
	public void const4()
	{
		byte _ = -8;
		byte a = -7;
		byte b = -6;
		byte c = -5;
		byte d = -4;
		byte e = -3;
		byte f = -2;
		byte g = -1;
		byte h = 0;
		byte i = 1;
		byte j = 2;
		byte k = 3;
		byte l = 4;
		byte m = 5;
		byte n = 6;
		byte o = 7;
		System.out.println("" + _ + a + b + c + d + e + f + g + h + i + j + k + l + m + n + o);
	}
	
	public static void main(String [] z)
	{
		int a = 5;
		switch(a)
		{
		case 1:
		case 2:
			System.out.println("1 || 2");
			break;
		case 3:
			System.out.print("3 || ");
		case 4:
		default:
			System.out.println("4");
			break;
		case 5:
			System.out.println("5");
		}
		TestDefaultPackage p = new TestDefaultPackage();
		TestInnerClass t = p.new TestInnerClass(3, 4);
		TestInnerClass.TestInnerInnerClass t2 = t.new TestInnerInnerClass(3, 4);
		System.out.println("t.a = " + t.a);
	}
}
