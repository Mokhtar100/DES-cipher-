/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import static des.Des.bin2hex;
import static des.Des.functionF;
import static des.Des.msgToBinary;
import static des.Des.splitLR;
import static des.Des.xor;

/**
 *
 * @author DELL PRECISION 5530
 */
public class desEncrypt {
    
      public static String encrypt(String msg, String[] keys) {
    String msgBinary = msgToBinary(msg);

    // L0 and R0
    String[] lr = splitLR(msgBinary);
    String LnMinus1 = lr[0];
    String RnMinus1 = lr[1];

    for (int n = 0; n < 16; n++) {
        //  Rn = Ln-1 + f(Rn-1, Kn)
        String fResult = functionF(RnMinus1, keys[n]);
        String Rn = xor(LnMinus1, fResult);

        //To check L16 and R16
        if (n == 15) {
            System.out.println("Iteration " + (n + 1) + ":");
            System.out.println("Ln: " + RnMinus1);
            System.out.println("Rn: " + Rn);
        }
     
        LnMinus1 = RnMinus1;
        RnMinus1 = Rn;
    }

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
    String inputBlock = RnMinus1 + LnMinus1;
    for (int index : IP_1) {
        permutedInput.append(inputBlock.charAt(index - 1));
    }
     System.out.println("Binary String: " + permutedInput.toString());

    
    return bin2hex(permutedInput.toString()) ;
}
      
    
    
    
    
}
