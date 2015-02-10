import java.io.PrintStream;

public class Test1 {
    public int value;
    public int value2;
    
    public Test1() {
      this.value = 100;
      this.value2 = 200;
    }

    public int test_base(int _value, int _value2) {
      int y = 0;
      
      System.out.println("VALUE = " + this.value + " VALUE 2 = " + this.value2);

      for(int i = 0; i < (_value + _value2); i++) {
         y = this.value + y - this.value2;
         y = y & 200 * test1(20);

         y = this.value2 - y;
      }

      if (this.value > 0) {
         this.value2 = y;
      }

      switch(this.value) {
         case 0 : this.value2 = this.pouet();
         default : this.value2 = this.pouet2();
      }
      
      switch(this.value) {
         case 1 : this.value2 = this.pouet();
         case 2 : this.value2 = this.pouet2();
         case 3 : this.value2 = this.pouet3();
      }

      return y;
    }

    public int pouet() {
      int v  = this.value;
      return v;
    }

    public int pouet2() {
      return 90;
    }

    public int pouet3() {
      return 80;
    }

    public int test1(int val) {
      int a = 0x10;

      return val + a - 60 * this.value;
    }

    public int go() {
      System.out.println(" test_base(500, 3) " + this.test_base( 500, 3 ) );

      return 0;
    }    
}
