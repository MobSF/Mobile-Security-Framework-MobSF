package tests.androguard;

public class TestQuickSort {
	public int a = 10;
	
	public static void Main(String[] args) {
		int[] intArray = new int[args.length];
		for (int i = 0; i < intArray.length; i++) {
			intArray[i] = Integer.parseInt(args[i]);
		}
		QuickSort(intArray, 0, intArray.length - 1);
		for (int i = 0; i < intArray.length; i++) {
			System.out.println(intArray[i] + " ");
		}
	}

	public static void QuickSort(int[] array, int left, int right) {
		if (right > left) {
			int pivotIndex = (left + right) / 2;
			int pivotNew = Partition(array, left, right, pivotIndex);
			QuickSort(array, left, pivotNew - 1);
			QuickSort(array, pivotNew + 1, right);
		}
	}

	static int Partition(int[] array, int left, int right, int pivotIndex) {
		int pivotValue = array[pivotIndex];
		Swap(array, pivotIndex, right);
		int storeIndex = left;
		for (int i = left; i < right; i++) {
			if (array[i] <= pivotValue) {
				Swap(array, storeIndex, i);
				storeIndex++;
			}
		}
		Swap(array, right, storeIndex);
		return storeIndex;
	}

	static void Swap(int[] array, int index1, int index2) {
		int tmp = array[index1];
		array[index1] = array[index2];
		array[index2] = tmp;
	}
}
