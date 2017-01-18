package org.t0t0.androguard.TC;                                                                                                                                                                                                   

public class TCD {
   public int TC1 = 1337;
   private int TC2 = -90000;

   public String equal(int a, String b)
   {
      String c = Integer.toString( a );

      System.out.print(c + " " + b + " ---- ");
      if (c.equals(b)) {
         return " OK ";
      }

      return "  X ";
   }

   public TCD()
   {
      System.out.println("TCD TC1 == 1337 : " + this.equal( this.TC1, "1337" ));
      System.out.println("TCD TC2 == -90000 : " + this.equal( this.TC2, "-90000" ));
      TC1 = 20;
      System.out.println("TCD TC1 == 20 : " + this.equal( this.TC1, "20" ));
   
      TCE e = new TCE();
      e.T1();
   }

   public void T1()
   {
   }
}
