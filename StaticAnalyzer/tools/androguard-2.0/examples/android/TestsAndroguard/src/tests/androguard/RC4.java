package tests.androguard;

public class RC4 {

public static void rc4_crypt(byte[] key, byte[] data) {
    int keylen = key.length;
    int datalen = data.length;
    int i;
    int j;
    
    // key scheduling
    byte[] sbox = new byte[256];
    for(i = 0; i < 256; i++) {
        sbox[i] = (byte)i;
    }
    j = 0;
    for(i = 0; i < 256; i++) {
        j = ((j + sbox[i] + key[i % keylen]) % 256) & 0xFF;
        byte tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
    
    // generate output
    i = 0;
    j = 0;
    int index = 0;
    while(index < datalen) {
        i = ((i + 1) % 256) & 0xFF;
        j = ((j + sbox[i]) % 256) & 0xFF;
        
        byte tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
        
        byte k = (byte)(sbox[((sbox[i] + sbox[j]) % 256) & 0xFF]);
        data[index] ^= k;
        index++;
    }
}
}