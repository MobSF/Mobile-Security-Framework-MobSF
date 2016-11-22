package tests.androguard;

public class Eratosthene {
	public static int[] eratosthenes(int n) {
	    boolean a[] = new boolean[n+1];
	    a[0] = true;
	    a[1] = true;
	    
	    int sqn = (int)Math.sqrt(n);
	    for(int i = 2; i <= sqn; i++) {
	        if(!a[i]) {
	            int j = i*i;
	            while(j <= n) {
	                a[j] = true;
	                j += i;
	            }
	        }
	    }
	    
	    int cnt = 0;
	    for(boolean b: a) {
	        if(!b) {
	            cnt++;
	        }
	    }
	    
	    int j = 0;
	    int[] primes = new int[cnt];
	    for(int i = 0; i < a.length; i++) {
	        if(!a[i]) {
	            primes[j++] = i;
	        }
	    }
	    return primes;
	}
}
