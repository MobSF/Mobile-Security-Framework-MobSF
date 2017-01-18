package org.t0t0.androguard.TCDiff;                                                                                                                                                                                                   

public class TCC {
   public int TC1 = 30;
   private int TC2 = -6;

   public String equal(int a, String b)
   {
      String c = Integer.toString( a );

      System.out.print(c + " " + b + " ---- ");
      if (c.equals(b)) {
         return " OK ";
      }

      return "  X ";
   }

   public TCC()
   {
      System.out.println("TCC TC1 == 30 : " + this.equal( this.TC1, "30" ));
      System.out.println("TCC TC2 == -6 : " + this.equal( this.TC2, "-6" ));
      TC1 = 20;
      System.out.println("TCC TC1 == 20 : " + this.equal( this.TC1, "20" ));
   }

   public void T1()
   {
   }
}
