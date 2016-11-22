package tests.androguard;

public class TestQuickSort2 {

	public int a = 10;
	
	public static void Main(String[] args) {
		int[] intArray = new int[args.length];
		for (int i = 0; i < intArray.length; i++) {
			intArray[i] = Integer.parseInt(args[i]);
		}
		quicksort(intArray, 0, intArray.length - 1);
		for (int i = 0; i < intArray.length; i++) {
			System.out.println(intArray[i] + " ");
		}
	}

	public static void quicksort(int[] array, int lo, int hi) {
	    int i = lo;
	    int j = hi;

	    int pivot = array[lo + (hi - lo) / 2];

	    while(i <= j) {

	        while(array[i] < pivot) {
	            i++;
	        }

	        while(array[j] > pivot) {
	            j--;
	        }

	        if(i <= j) {
	            int temp = array[i];
	            array[i] = array[j];
	            array[j] = temp;
	            i++;
	            j--;
	        }
	    }

	    if(lo < j) {
	        quicksort(array, lo, j);
	    }
	    
	    if(i < hi) {
	        quicksort(array, i, hi);
	    }
	}
}
