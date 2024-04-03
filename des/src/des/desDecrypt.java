/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import static des.Des.bin2hex;
import static des.Des.functionF;
import static des.Des.generateKeys;
import static des.Des.hex2bin;
import static des.Des.initialPermutation;
import static des.Des.splitLR;
import static des.Des.toBinary;
import static des.Des.xor;

/**
 *
 * @author Mokhtar
 */
public class desDecrypt {

    public static String decrypt(String encryptedMsg, String key) {

        String encryptedBinary = hex2bin(encryptedMsg);
        String[] keys = generateKeys(toBinary(key));
        String permutedMessage = initialPermutation(encryptedBinary);

        String[] lr = splitLR(permutedMessage);
        String Ln = lr[0];
        String Rn = lr[1];

        for (int n = 15; n >= 0; n--) {

            String fResult = functionF(Rn, keys[n]);
            String nextRn = xor(Ln, fResult);
            Ln = Rn;
            Rn = nextRn;
            // System.out.println("Ln: " + Ln + ", Rn: " + Rn);
        }

        String temp = Ln;
        Ln = Rn;
        Rn = temp;
// System.out.println( " Ln: " + Ln + ", Rn: " + Rn);

        int[] IP_1 = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };

        StringBuilder permutedInput = new StringBuilder();
        String merged = Ln + Rn;
        for (int index : IP_1) {
            permutedInput.append(merged.charAt(index - 1));
        }

        return bin2hex(permutedInput.toString());
    }

}
