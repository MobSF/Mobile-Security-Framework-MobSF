package org.t0t0.androguard.TCDiff;                                                                                                                                                                                                   

public class TCE {
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

   public TCE()
   {
      System.out.println("TCE TC1 == 1337 : " + this.equal( this.TC1, "1337" ));
      System.out.println("TCE TC2 == -90000 : " + this.equal( this.TC2, "-90000" ));
      
      this.TC1 = 20;
      System.out.println("TCE TC1 == 20 : " + this.equal( this.TC1, "20" ));

      this.TC2 = -30;
      System.out.println("TCE TC2 == -30 : " + this.equal( this.TC2, "-30" ));

      int y = 0;
      for(int i = 0; i < (this.TC1 - this.TC2); i++) {
         for(int j=0; j < i; j++) {
            y = y + this.TCE_t1( 400 );
         } 

         switch( this.TC1 ) {
            case 0 : y += 1;
            default : y = y + this.TCE_t2();
         } 

         switch( this.TC2 ) {
            case 0 : y += 30;
            case 45 : y += 2;
            case -6 : y = y + this.TCE_t3();
         }
      }

      this.TC1 = y;

      System.out.println("TCE TC1 == 3433300 : " + this.equal( this.TC1, "3433300" ));

      TCC c = new TCC();
      c.T1();
   }

   public int TCE_t1(int a)
   {
      return a * 7;
   }

   public int TCE_t2()
   {
      return 0x42;
   }
   
   public int TCE_t3()
   {
      return 0x45;
   }

   // NEW METHOD
   public int TCE_t4()
   {
      return 0x90;
   }

   public void T1()
   {
   }
}
