package tests.androguard;

public class Lzss {
	public static int lzss_decompress(byte[] in, byte[] out) {
	    int i = 0;
	    int j = 0;
	    int flags = 0;
	    int cnt = 7;
	    
	    while(j < out.length) {

	        if(++cnt == 8) {
	            if(i >= in.length) {
	                break;
	            }
	            flags = in[i++] & 0xFF;
	            cnt = 0;
	        }
	        
	        if((flags & 1) == 0) {
	            if(i >= in.length) {
	                break;
	            }
	            out[j] = in[i];
	            j++;
	            i++;
	        }
	        else {
	            if((i + 1) >= in.length) {
	                return -1;
	            }
	            int v = (in[i] & 0xFF) | (in[i+1] & 0xFF) << 8;
	            i += 2;
	            
	            int offset = (v >> 4) + 1;
	            int length = (v & 0xF) + 3;

	            // not enough data decoded
	            if(offset > j) {
	                return -1;
	            }

	            // output buffer is too small
	            if((out.length - j) < length) {
	                return -1;
	            }

	            for(int k = 0; k < length; k++) {
	                out[j+k] = out[j+k-offset];
	            }
	            j += length;
	        }

	        flags >>= 1;
	    }

	    return j;
	}
}
