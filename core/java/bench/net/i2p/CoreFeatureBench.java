package net.i2p;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import net.i2p.crypto.AESEngine;
import net.i2p.crypto.ChaCha20;
import net.i2p.crypto.EncType;
import net.i2p.crypto.HMAC256Generator;
import net.i2p.crypto.KeyGenerator;
import net.i2p.crypto.SHA256Generator;
import net.i2p.crypto.SipHashInline;
import net.i2p.crypto.x25519.X25519DH;
import net.i2p.data.Base64;
import net.i2p.data.ByteArray;
import net.i2p.data.DataHelper;
import net.i2p.data.Hash;
import net.i2p.data.Payload;
import net.i2p.data.PrivateKey;
import net.i2p.data.PublicKey;
import net.i2p.data.SessionKey;
import net.i2p.data.i2cp.BandwidthLimitsMessage;
import net.i2p.data.i2cp.I2CPMessageHandler;
import net.i2p.kademlia.KBucketSet;
import net.i2p.util.ByteCache;
import net.i2p.util.LHMCache;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 2, time = 500, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Thread)
public class CoreFeatureBench {
    private I2PAppContext ctx;
    private byte[] data;
    private String base64Text;
    private byte[] longBuffer;
    private byte[] dateBuffer;
    private byte[] gzipSource;
    private byte[] gzipData;
    private byte[] hashInput;
    private byte[] digest;
    private SHA256Generator sha;
    private HMAC256Generator hmac;
    private byte[] hmacKey;
    private byte[] hmacOutput;
    private AESEngine aes;
    private SessionKey aesKey;
    private byte[] aesIv;
    private byte[] aesPlain;
    private byte[] aesCipher;
    private byte[] aesDecrypted;
    private byte[] chachaKey;
    private byte[] chachaIv;
    private byte[] chachaPlain;
    private byte[] chachaCipher;
    private byte[] chachaDecrypted;
    private PrivateKey x25519Private;
    private PublicKey x25519Public;
    private byte[] pbeSalt;
    private byte[] pbePassphrase;
    private Payload payload;
    private byte[] payloadWire;
    private BandwidthLimitsMessage i2cpMessage;
    private byte[] i2cpWire;
    private KBucketSet<Hash> kBucketSet;
    private Hash kademliaQuery;
    private LHMCache<Integer, Integer> lhmCache;
    private ByteCache byteCache;
    private int lhmKey;

    @Setup
    public void setup() throws Exception {
        ctx = I2PAppContext.getGlobalContext();
        data = new byte[1024];
        for (int i = 0; i < data.length; i++)
            data[i] = (byte) (i * 31 + 7);
        base64Text = Base64.encode(data);
        longBuffer = new byte[8];
        DataHelper.toLong(longBuffer, 0, 8, 0x0102030405060708L);
        dateBuffer = new byte[8];
        DataHelper.toDate(dateBuffer, 0, 1700000000000L);
        gzipSource = new byte[8192];
        for (int i = 0; i < gzipSource.length; i++)
            gzipSource[i] = (byte) (i / 32);
        gzipData = DataHelper.compress(gzipSource);
        sha = ctx.sha();
        hashInput = new byte[Hash.HASH_LENGTH];
        for (int i = 0; i < hashInput.length; i++)
            hashInput[i] = (byte) (i * 13 + 3);
        digest = new byte[Hash.HASH_LENGTH];
        hmac = ctx.hmac256();
        hmacKey = new byte[32];
        for (int i = 0; i < hmacKey.length; i++)
            hmacKey[i] = (byte) (i * 17 + 5);
        hmacOutput = new byte[Hash.HASH_LENGTH];
        hmac.calculate(hmacKey, data, 0, data.length, hmacOutput, 0);
        aes = ctx.aes();
        aesKey = new SessionKey(fixedBytes(32, 0x41));
        aesIv = fixedBytes(16, 0x52);
        aesPlain = fixedBytes(512, 0x63);
        aesCipher = new byte[aesPlain.length];
        aesDecrypted = new byte[aesPlain.length];
        aes.encrypt(aesPlain, 0, aesCipher, 0, aesKey, aesIv, aesPlain.length);
        chachaKey = fixedBytes(32, 0x71);
        chachaIv = fixedBytes(12, 0x72);
        chachaPlain = fixedBytes(1024, 0x73);
        chachaCipher = new byte[chachaPlain.length];
        chachaDecrypted = new byte[chachaPlain.length];
        ChaCha20.encrypt(chachaKey, chachaIv, chachaPlain, 0, chachaCipher, 0, chachaPlain.length);
        byte[] xPrivateBytes = DataHelper.fromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        byte[] xPublicBytes = DataHelper.fromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        if (xPrivateBytes.length == 33)
            xPrivateBytes = Arrays.copyOfRange(xPrivateBytes, 1, xPrivateBytes.length);
        if (xPublicBytes.length == 33)
            xPublicBytes = Arrays.copyOfRange(xPublicBytes, 1, xPublicBytes.length);
        xPublicBytes[31] &= 0x7f;
        x25519Private = new PrivateKey(EncType.ECIES_X25519, xPrivateBytes);
        x25519Public = new PublicKey(EncType.ECIES_X25519, xPublicBytes);
        pbeSalt = fixedBytes(16, 0x81);
        pbePassphrase = fixedBytes(24, 0x82);
        payload = new Payload();
        payload.setEncryptedData(fixedBytes(256, 0x91));
        payloadWire = new byte[4 + payload.getSize()];
        payload.writeBytes(payloadWire, 0);
        i2cpMessage = new BandwidthLimitsMessage(256, 512);
        ByteArrayOutputStream i2cpOut = new ByteArrayOutputStream();
        i2cpMessage.writeMessage(i2cpOut);
        i2cpWire = i2cpOut.toByteArray();
        kBucketSet = new KBucketSet<Hash>(ctx, new Hash(fixedBytes(Hash.HASH_LENGTH, 1)), 8, 1);
        for (int i = 1; i < 32; i++)
            kBucketSet.add(new Hash(fixedBytes(Hash.HASH_LENGTH, i + 1)));
        kademliaQuery = new Hash(fixedBytes(Hash.HASH_LENGTH, 16));
        lhmCache = new LHMCache<Integer, Integer>(64);
        for (int i = 0; i < 64; i++)
            lhmCache.put(i, i);
        byteCache = ByteCache.getInstance(64, 1024);
    }

    @Setup(Level.Iteration)
    public void resetLhm() {
        lhmKey = 0;
    }

    @Benchmark
    public String base64Encode() {
        return Base64.encode(data);
    }

    @Benchmark
    public byte[] base64Decode() {
        return Base64.decode(base64Text);
    }

    @Benchmark
    public void integerEncode(Blackhole blackhole) {
        DataHelper.toLong(longBuffer, 0, 8, 0x0102030405060708L);
        blackhole.consume(longBuffer);
    }

    @Benchmark
    public long integerDecode() {
        return DataHelper.fromLong(longBuffer, 0, 8);
    }

    @Benchmark
    public void dateEncode(Blackhole blackhole) {
        DataHelper.toDate(dateBuffer, 0, 1700000000000L);
        blackhole.consume(dateBuffer);
    }

    @Benchmark
    public Object dateDecode() throws Exception {
        return DataHelper.fromDate(dateBuffer, 0);
    }

    @Benchmark
    public byte[] gzipCompress() {
        return DataHelper.compress(gzipSource);
    }

    @Benchmark
    public byte[] gzipDecompress() throws Exception {
        return DataHelper.decompress(gzipData);
    }

    @Benchmark
    public Hash hashCreate() {
        return Hash.create(hashInput, 0);
    }

    @Benchmark
    public void sha256(Blackhole blackhole) {
        sha.calculateHash(data, 0, data.length, digest, 0);
        blackhole.consume(digest);
    }

    @Benchmark
    public long sipHash() {
        return SipHashInline.hash24(0x0706050403020100L, 0x0f0e0d0c0b0a0908L, data);
    }

    @Benchmark
    public void aesEncrypt(Blackhole blackhole) {
        aes.encrypt(aesPlain, 0, aesCipher, 0, aesKey, aesIv, aesPlain.length);
        blackhole.consume(aesCipher);
    }

    @Benchmark
    public void aesDecrypt(Blackhole blackhole) {
        aes.decrypt(aesCipher, 0, aesDecrypted, 0, aesKey, aesIv, aesCipher.length);
        blackhole.consume(aesDecrypted);
    }

    @Benchmark
    public void chachaEncrypt(Blackhole blackhole) {
        ChaCha20.encrypt(chachaKey, chachaIv, chachaPlain, 0, chachaCipher, 0, chachaPlain.length);
        blackhole.consume(chachaCipher);
    }

    @Benchmark
    public void chachaDecrypt(Blackhole blackhole) {
        ChaCha20.decrypt(chachaKey, chachaIv, chachaCipher, 0, chachaDecrypted, 0, chachaCipher.length);
        blackhole.consume(chachaDecrypted);
    }

    @Benchmark
    public SessionKey x25519Dh() {
        return X25519DH.dh(x25519Private, x25519Public);
    }

    @Benchmark
    public PublicKey x25519PublicKey() {
        return KeyGenerator.getPublicKey(x25519Private);
    }

    @Benchmark
    public SessionKey pbeSessionKey() {
        return KeyGenerator.getInstance().generateSessionKey(pbeSalt, pbePassphrase);
    }

    @Benchmark
    public void hmacSha256(Blackhole blackhole) {
        hmac.calculate(hmacKey, data, 0, data.length, hmacOutput, 0);
        blackhole.consume(hmacOutput);
    }

    @Benchmark
    public boolean hmacVerify() {
        return hmac.verify(new SessionKey(hmacKey), data, 0, data.length, hmacOutput, 0, hmacOutput.length);
    }

    @Benchmark
    public List<Hash> kademliaClosest() {
        return kBucketSet.getClosest(kademliaQuery, 16);
    }

    @Benchmark
    public Integer lhmGet() {
        return lhmCache.get(lhmKey);
    }

    @Benchmark
    public Integer lhmPut() {
        lhmKey = (lhmKey + 1) & 127;
        return lhmCache.put(lhmKey, lhmKey);
    }

    @Benchmark
    public void byteCacheCycle() {
        ByteArray entry = byteCache.acquire();
        byteCache.release(entry);
    }

    @Benchmark
    public void i2cpWrite() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        i2cpMessage.writeMessage(out);
    }

    @Benchmark
    public Object i2cpRead() throws Exception {
        return I2CPMessageHandler.readMessage(new ByteArrayInputStream(i2cpWire));
    }

    @Benchmark
    public int payloadWrite() {
        return payload.writeBytes(payloadWire, 0);
    }

    @Benchmark
    public Object payloadRead() throws Exception {
        Payload read = new Payload();
        read.readBytes(new ByteArrayInputStream(payloadWire));
        return read;
    }

    private static byte[] fixedBytes(int length, int seed) {
        byte[] rv = new byte[length];
        for (int i = 0; i < length; i++)
            rv[i] = (byte) (seed + i * 29);
        return rv;
    }

    public static void main(String[] args) throws RunnerException {
        Options options = new OptionsBuilder()
                .include(CoreFeatureBench.class.getSimpleName())
                .build();
        new Runner(options).run();
    }
}
