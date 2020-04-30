import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.File;
import java.security.NoSuchProviderException;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

public class PgpEncrypt {

        private static final BouncyCastleProvider provider = new BouncyCastleProvider();
        static
        {
            Security.addProvider( provider );
        }
	public static void main(String[] args) {

try{
 ByteArrayInputStream	in = new ByteArrayInputStream("-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: Keybase OpenPGP v1.0.0\nComment: https://keybase.io/crypto\n\nxo0EXqmUlAEEANDZakx/45HGTb083ITuK6lFJxbJ+oSqpUI8MsLkFJ8xa3k5d38Y\n5K7GhzPkRq7nKqWgtozHnYRICU7uthgYH7Ub7PDtICaPLlhZl0UgfefdjtqtiOy5\nzcT9iV6fYtdGggsxkKHuMYGkMEO3d7Pn1+eailhTR0nNqfzQwV6O9BXfABEBAAHN\nI2Fuc2h1bWFuIDxhbnNodXNhaWtpYTU1NUBnbWFpbC5jb20+wq0EEwEKABcFAl6p\nlJQCGy8DCwkHAxUKCAIeAQIXgAAKCRBSGbsSdOUnQ3hpBACd/yE4ROebqDvyt//H\nTvXosViYBOUAUdnpaPkmAGJd+uAuixN0uxoVamVfxclnFr7nTp9dZUkrPBqrclQu\nNw4zLeWwmGuO8DmdqE/vOL+g0k5OYV6hJPjsUBYTxZnjLvfxLEPNYRZl0M2cvdkN\njYTl6xTQDsN1f2e7G22LSo3rYM6NBF6plJQBBADd6sGHfIcAdSUm7SVLOW6A5LuK\n2s0Xm28EKktiqKWiIIhh9qDnpq/k2KV9oI6JjwMDmknYpxvLUYUtUZKCQu94T/C0\nwbXDwIL9nbBNvctL1BOgkQ1uwa13g/ZABTrE8LIRTj1Inm6GHSozGwCfthMcvV2+\nk4BEWou5gzd3XvKXDwARAQABwsCDBBgBCgAPBQJeqZSUBQkPCZwAAhsuAKgJEFIZ\nuxJ05SdDnSAEGQEKAAYFAl6plJQACgkQjIjDc1W7DoN7IQP/bQX9ANDro8YqKk2g\ndEpTJ2QEJjNaP4L7NWK28vVSS7fZKGjAeeW2K+djAM6/uT4gswfKxb4CeIstNHOb\nkuepp0X6gsjHf6l1yUS8AR1+Gg//mQBBTxPop9L47uZB7z3T3Zb3iKK5P1wzGBoI\nqlamvliWRvmjbK4kaRXEJmtb9nCMXwP+OEQppUAwF+iDkJII7eqzisbJkn1yNEF1\nMIOANVj46iDuBXs7LWQ/+ynwNJ9M3e+pY+O08YADxKsJiKgieELn8k7/Paa2CJq1\nj/63UGwTeMogZ5RP6M68+sKUupIYkPpbuZIxu7v7NEPNyUVRB1Wtlay1OBE3XTyR\nb/46LrymUZnOjQReqZSUAQQA93mMeM+utNgJZCoo1Qv0wpys8ZTtKCthdyKO79ko\nJM+B7YDPDErJqyKPrTCSfkmqB36qZQ8BnrA2EdLi0DCS1mu4QKcSjfZMWAbOGgNs\nBzsREWTF0pcXS8rm4dUGzLZjKxXJmVozBYzkoDSRugFzyM30VZUhfRU7Vv947I25\nGfcAEQEAAcLAgwQYAQoADwUCXqmUlAUJDwmcAAIbLgCoCRBSGbsSdOUnQ50gBBkB\nCgAGBQJeqZSUAAoJEBc4xQjQ4FgFpCAD/1Tsy/HBLteXGHSEF8KElYP1iDSgMoFO\ngtXbbQQ/5CSAld4GVrbaJ7S1LbFAux4OY6wsPNgzUyK7FxhCuJ46dLlIoXg7QGQj\nJ66pikUyPG9mkRJQc2Bu4VOpkyQp7YpTNjlwtJKmZwSyDzCEVikSKvUB/syqvqtf\nD+bMFWIsA3RvWL4EALtXT/o9RpWp7WzoVz6MFUT1b1T1jr5CWGhOuFrNgbtKAU62\nC4d2nGoajdtr/eWoDXQy5IKbB/GLAOSzff2LiATTOzjxcNlA/7qn1HJH6csfrL/o\nYK/8AAmvDp/n4N4L1TFIgAkc8hv8eHAhFQrPGNHVd0+t4ypYkfyLdLIpt6XZ\n=AC7c\n-----END PGP PUBLIC KEY BLOCK-----".getBytes());
        PGPPublicKey publicKey = readPublicKey(in);

        String str = "Hii anshuman";
        byte[] byteArr = str.getBytes();
    
        String s = new String(byteArr);
System.out.println("-----------------------------------\noriginal message: "+s);
byte[] byteArr1 = encrypt( byteArr,  publicKey, true );
String s1 = new String(byteArr1);
System.out.println("-----------------------------\nencrypted message\n"+s1);

ByteArrayInputStream	secKey = new ByteArrayInputStream("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: Keybase OpenPGP v1.0.0\nComment: https://keybase.io/crypto\n\n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\n8hv8eHAhFQrPGNHVd0+t4ypYkfyLdLIpt6XZ\n=wVgO\n-----END PGP PRIVATE KEY BLOCK-----".getBytes());
byte[] decrypted = decrypt(byteArr1, secKey, "passphrase".toCharArray());

System.out.println("---------------------------\ndecrypted data = '" + new String(decrypted) + "'");

} catch (PGPException e) {
        System.out.println(e.toString());
        System.out.println(e.getUnderlyingException().toString());
        
} catch (Exception e) {
        System.out.println(e.toString());
}		
	}	
        public static byte[] encrypt( final byte[] message, final PGPPublicKey publicKey, boolean armored )
        throws PGPException
{
    try
    {
        final ByteArrayInputStream in = new ByteArrayInputStream( message );
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        final PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();
        final PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator( CompressionAlgorithmTags.ZIP );
        final OutputStream pOut =
                literal.open( comData.open( bOut ), PGPLiteralData.BINARY, "filename", in.available(), new Date() );
        Streams.pipeAll( in, pOut );
        comData.close();
        final byte[] bytes = bOut.toByteArray();
        final PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder( SymmetricKeyAlgorithmTags.AES_256 ).setWithIntegrityPacket( true )
                                                                                   .setSecureRandom(
                                                                                           new SecureRandom() )

                                                                                   .setProvider( provider ) );
        generator.addMethod( new JcePublicKeyKeyEncryptionMethodGenerator( publicKey ).setProvider( provider ) );
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        OutputStream theOut = armored ? new ArmoredOutputStream( out ) : out;
        OutputStream cOut = generator.open( theOut, bytes.length );
        cOut.write( bytes );
        cOut.close();
        theOut.close();
        return out.toByteArray();
    }
    catch ( Exception e )
    {
        throw new PGPException( "Error in encrypt", e );
    }
}

static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException
{
    InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
    PGPPublicKey pubKey = readPublicKey(keyIn);
    keyIn.close();
    return pubKey;
}
    
	
  static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                if (key.isEncryptionKey())
                {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }	
    public static String decrypt(String passphrase, String keyFile, String encryptedStr)
    throws Exception {

byte[] decrypted = decryptByte(passphrase, keyFile, encryptedStr.getBytes());

return new String(decrypted);
}

public static String decryptFile(String passphrase, String keyFile, String inputFile)
    throws Exception {

byte[] encFromFile = getBytesFromFile(new File(inputFile));
byte[] decrypted = decryptByte(passphrase, keyFile, encFromFile);

return new String(decrypted);

}

private static PGPPrivateKey extractPrivateKey(PGPSecretKey pgpSecKey, char[] passPhrase)
    throws PGPException {
PGPPrivateKey privateKey = null;
BcPGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();
BcPBESecretKeyDecryptorBuilder secretKeyDecryptorBuilder = new BcPBESecretKeyDecryptorBuilder(
        calculatorProvider);
PBESecretKeyDecryptor pBESecretKeyDecryptor = secretKeyDecryptorBuilder.build(passPhrase);

try {
    privateKey = pgpSecKey.extractPrivateKey(pBESecretKeyDecryptor);
} catch (PGPException e) {
    throw new PGPException("invalid privateKey passPhrase: " + String.valueOf(passPhrase),
            e);
}

return privateKey;
}

@SuppressWarnings("unchecked")
protected static byte[] decrypt(byte[] encrypted, InputStream keyIn, char[] password)
    throws IOException, PGPException, NoSuchProviderException {

InputStream decodeIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(encrypted));
BcPGPObjectFactory pgpF = new BcPGPObjectFactory(decodeIn);
decodeIn.close();

PGPEncryptedDataList enc = null;
Object o = pgpF.nextObject();

//
// the first object might be a PGP marker packet.
//
if (o instanceof PGPEncryptedDataList) {
    enc = (PGPEncryptedDataList) o;
} else {
    enc = (PGPEncryptedDataList) pgpF.nextObject();
}

// find the secret key

PGPPrivateKey sKey = null;









//Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
PGPPublicKeyEncryptedData pbe = null;
PGPSecretKeyRingCollection pgpSec = new BcPGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(keyIn));

// while (sKey == null && it.hasNext()) {
//     pbe = it.next();
//     sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);

// }

for (int i = 0; i < enc.size() && sKey == null; i++) {
        Object encryptedData = enc.get(i);
      
        pbe = (PGPPublicKeyEncryptedData) encryptedData;
        sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
       
      }



// ////
// PGPSecretKey secretKey = readSecretKey(keyIn);
// sKey = getPGPSecretKey(secretKey, password);
// ///

// if (pbe == null) {
//     throw new IllegalArgumentException("PGPPublicKeyEncryptedData not found.");
// }

if (sKey == null) {
    throw new IllegalArgumentException("secret key for message not found.");
}

BcPublicKeyDataDecryptorFactory pkdf = new BcPublicKeyDataDecryptorFactory(sKey);

InputStream clear = pbe.getDataStream(pkdf);
PGPObjectFactory pgpFact = new BcPGPObjectFactory(clear);

PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();

pgpFact = new BcPGPObjectFactory(cData.getDataStream());

PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

InputStream unc = ld.getInputStream();

ByteArrayOutputStream out = new ByteArrayOutputStream();
int ch;

while ((ch = unc.read()) >= 0) {
    out.write(ch);

}

byte[] returnBytes = out.toByteArray();
clear.close();
out.close();
unc.close();

return returnBytes;

}

protected static byte[] decryptByte(String passphrase, String keyFile, byte[] encryptedBytes)
    throws Exception {
Security.addProvider(new BouncyCastleProvider());

FileInputStream secKey = new FileInputStream(keyFile);
byte[] decrypted = decrypt(encryptedBytes, secKey, passphrase.toCharArray());

return decrypted;
}

protected static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID,
    char[] pass) throws PGPException, NoSuchProviderException {
PGPPrivateKey privateKey = null;
PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

if (pgpSecKey == null) {
    return null;
}
privateKey = extractPrivateKey(pgpSecKey, pass);

return privateKey;
}




public static byte[] getBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);
 
        // Get the size of the file
        long length = file.length();
 
        if (length > Integer.MAX_VALUE) {
            // File is too large
        }
 
        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];
 
        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
               && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
            offset += numRead;
        }
 
        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            is.close();
            throw new IOException("Could not completely read file "+file.getName());

        }
 
        // Close the input stream and return bytes
        is.close();
        return bytes;
    }














    

    

}
