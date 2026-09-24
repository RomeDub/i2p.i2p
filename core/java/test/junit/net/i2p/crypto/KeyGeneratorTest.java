package net.i2p.crypto;
/*
 * free (adj.): unencumbered; not under the control of others
 * Written by jrandom in 2003 and released into the public domain 
 * with no warranty of any kind, either expressed or implied.  
 * It probably won't make your computer catch on fire, or eat 
 * your children, but it might.  Use at your own risk.
 *
 */
 
import java.security.MessageDigest;

import junit.framework.TestCase;
import net.i2p.I2PAppContext;
import net.i2p.data.DataHelper;
import net.i2p.data.PrivateKey;
import net.i2p.data.PublicKey;
import net.i2p.data.Signature;
import net.i2p.data.SigningPrivateKey;
import net.i2p.data.SigningPublicKey;
import net.i2p.data.SessionKey;
import net.i2p.util.RandomSource;

public class KeyGeneratorTest extends TestCase{
    public void testKeyGen(){
        RandomSource.getInstance().nextBoolean();
        byte src[] = new byte[200];
        RandomSource.getInstance().nextBytes(src);

        I2PAppContext ctx = I2PAppContext.getGlobalContext();
        for (int i = 0; i < 10; i++) {
            Object keys[] = KeyGenerator.getInstance().generatePKIKeypair();
            byte ctext[] = ctx.elGamalEngine().encrypt(src, (PublicKey) keys[0]);
            byte ptext[] = ctx.elGamalEngine().decrypt(ctext, (PrivateKey) keys[1]);
            assertTrue(DataHelper.eq(ptext, src));
        }

        Object obj[] = KeyGenerator.getInstance().generateSigningKeypair();
        SigningPublicKey fake = (SigningPublicKey) obj[0];
        for (int i = 0; i < 10; i++) {
            Object keys[] = KeyGenerator.getInstance().generateSigningKeypair();
            
            Signature sig = DSAEngine.getInstance().sign(src, (SigningPrivateKey) keys[1]);
            assertTrue(DSAEngine.getInstance().verifySignature(sig, src, (SigningPublicKey) keys[0]));
            assertFalse(DSAEngine.getInstance().verifySignature(sig, src, fake));
        }

        for (int i = 0; i < 1000; i++) {
            KeyGenerator.getInstance().generateSessionKey();
        }
    }

    public void testPbeSessionKey() throws Exception {
        byte[] salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] passphrase = new byte[] { 17, 18, 19, 20, 21, 22, 23, 24 };
        byte[] salted = new byte[16 + passphrase.length];
        System.arraycopy(salt, 0, salted, 0, salt.length);
        System.arraycopy(passphrase, 0, salted, 16, passphrase.length);
        MessageDigest digest = SHA256Generator.getDigestInstance();
        digest.update(salted);
        byte[] expected = digest.digest();
        for (int i = 1; i < 1000; i++) {
            digest.update(expected);
            digest.digest(expected, 0, expected.length);
        }
        SessionKey actual = KeyGenerator.getInstance().generateSessionKey(salt, passphrase);
        assertTrue(DataHelper.eq(actual.getData(), expected));
    }
}
