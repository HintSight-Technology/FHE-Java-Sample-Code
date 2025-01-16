package com.hintsight.n2he;

import static com.hintsight.n2he.Parameters.*;
import static com.hintsight.n2he.Utils.*;

public class Decryption {
    public static Boolean decrypt(long[] encryptedResult, int[] secretKey) {
        return true;
    }

    public static long lwe64Dec(long[] encryptedResult, int[] secretKey, int polySize) {
        //computing (b + <a, s>) mod q
        long alpha = getCiphertextModulus() / getPlaintextModulus();
        long result = encryptedResult[polySize];

        for (int i = 0; i < polySize; i++) {
            result += (encryptedResult[i] * (long)secretKey[i]);
            result = modq(result, getCiphertextModulus());
        }

        while (result < 0) {
            result += getCiphertextModulus();
        }

        result = (result + alpha/2) % getCiphertextModulus();
        result /= alpha;
        if (result > getPlaintextModulus()/2) {
            result -= getPlaintextModulus();
        }

        return result;
    }

    public static long[] rlwe64Dec(int polySize, long ciphertextModulus, long plaintextModulus, long[] secretKey, long[][] encryptedResult) {
        //compute as
        long[] as = mulPoly(secretKey, encryptedResult[0], polySize, ciphertextModulus);

        //compute b + as
        addPoly(as, encryptedResult[1], polySize, ciphertextModulus);

        //compute alpha
        double alpha = (double) plaintextModulus / (double) ciphertextModulus;

        //alpha * as
        for (int i = 0; i < polySize; i++) {
            double temp = alpha * (double) as[i];
            long temp2 = (long) temp;
            if (temp - (double) temp2 >= 0.5 && temp > 0) {
                temp2++;
            } else if ((double) temp2 - temp >= 0.5 && temp < 0) {
                temp2--;
            }
            as[i] = temp2;
        }

        return as;
    }
}
