package org.dematte.nfc.common;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;


/**
 * A class to wrap Mifare Desfire commands, using a generic "Communicator"
 * 
 * Commands and parameters from libfreefare (https://github.com/nfc-tools) 
 */
public class MifareDesfire {

    private final int macSize = 4;
    private final int maxDataSize = 52 - macSize;

    protected ICardCommunicator cardCommunicator;
    protected SecureRandom randomGenerator;
    public byte[] uid;

    public MifareDesfire(ICardCommunicator cardCommunicator, byte[] uid) throws NoSuchAlgorithmException {
        this.cardCommunicator = cardCommunicator;
        this.uid = uid;
        this.randomGenerator = new SecureRandom();
    }

    // Mifare Desfire specifications require DESede/ECB without padding
    protected Cipher getCipher(byte[] diversifiedKey)
            throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher chiper = Cipher.getInstance("DESede/ECB/NoPadding");

        ByteArray tripleDesKey = new ByteArray();
        if (diversifiedKey.length == 8) {
            tripleDesKey.append(diversifiedKey).append(diversifiedKey).append(diversifiedKey);
        } else if (diversifiedKey.length == 16) {
            byte[] firstKey = new byte[8];
            System.arraycopy(diversifiedKey, 0, firstKey, 0, 8);
            tripleDesKey.append(diversifiedKey).append(firstKey);
        } else if (diversifiedKey.length == 24) {
            tripleDesKey.append(diversifiedKey);
        } else
            throw new IllegalArgumentException("Wrong key length");

        // And we initialize it with our (diversified) read or write key
        final SecretKey key = new SecretKeySpec(tripleDesKey.toArray(), "DESede");
        chiper.init(Cipher.DECRYPT_MODE, key);

        return chiper;
    }

    /**
     * Returns a byte array that represents the card version
     *
     * @throws IOException
     */
    public byte[] getVersion() throws IOException {
        return sendBytes(new byte[]{0x60}).data;
    }

    public byte[] getApplications() throws IOException {
        return sendBytes(new byte[]{0x6a}).data;
    }

    public boolean selectApplication(byte[] applicationId) throws IOException {
        byte[] params = ByteArray.from((byte)0x5a).append(applicationId).toArray();
        byte[] res = cardCommunicator.transceive(params);

        if (res != null && res.length == 1 && res[0] == 0)
            return true;
        else
            return false;
    }

    /**
     * Get a list of all the files in the current application ("directory")
     */
    public byte[] getFileIds() throws IOException {
        return sendBytes(new byte[]{0x6f}).data;
    }

    public byte[] readRecordFile(byte fid, int start, int count) throws IOException {
        byte[] cmd = new ByteArray().append((byte)0xBB).append(fid).append(start, 3).append(count, 3).toArray();
        MifareResult result = sendBytes(cmd);
        return result.data;
    }

    public byte[] readFile(byte fid, int start, int count) throws IOException {
        ByteArray ret = new ByteArray();

        boolean done = false;
        int bytesToGo = count;

        while (!done) {

            int upTo;
            if (count == 0)
                upTo = maxDataSize;
            else
                upTo = Math.min(maxDataSize, bytesToGo);

            ByteArray array = new ByteArray();
            byte[] cmd = array.append((byte)0xBD).append(fid).append(start, 3).append(upTo, 3).toArray();

            MifareResult result = sendBytes(cmd);

            if (result.resultType == MifareResultType.EOF) {
                // We reached the end of the file.
                // Ensure we got anything that was left
                array.clear();
                cmd = array.append((byte)0xBD).append(fid).append(start, 3).append(0, 3).toArray();
                result = sendBytes(cmd);
                done = true;
            }

            ret.append(result.data);

            start += upTo;
            if (count > 0) {
                bytesToGo -= upTo;
                if (bytesToGo == 0)
                    done = true;
            }
        }
        return ret.toArray();
    }

    private void writeInternal(byte cmd, byte[] data, int file, int offset, int size) throws IOException {
        int data_size;

        if (size == 0)
            data_size = data.length;
        else
            data_size = size;

        int data_to_go = data_size;
        while (data_to_go > 0) {

            int bytes_to_write;

            if (data_to_go > maxDataSize)
                bytes_to_write = maxDataSize;
            else
                bytes_to_write = data_to_go;


            ByteArray args = new ByteArray();
            args.append(cmd).append((byte)file).append(offset, 3).append(bytes_to_write, 3)
                .append(data, offset, bytes_to_write);

            data_to_go -= maxDataSize;
            offset += maxDataSize;

            byte[] message = args.toArray();
            byte[] result = cardCommunicator.transceive(message);
            if (result == null || result.length == 0)
                throw new IOException("Transceive returned an empty response");

            if (result[0] != 0)
                throw new IOException("Transceive error: " + ByteArray.byteArrayToHexString(result));
        }
    }

    public void writeFile(byte[] data, int file, int offset, int size) throws IOException {
        writeInternal((byte)0x3D, data, file, offset, size);
    }

    public void commit() throws IOException {
        byte[] result = cardCommunicator.transceive(new byte[]{(byte)0xC7});
        if (result == null || result.length == 0)
            throw new IOException("Commit returned an empty response");

        if (!(result[0] == 0x00 || result[0] == 0x0C))
            throw new IOException("Commit error: " + ByteArray.byteArrayToHexString(result));
    }

    public byte[] getFileSettings(byte fid) throws IOException {
        return sendBytes(new byte[]{(byte)0xf5, fid}).data;
    }

    public byte[] getKeySettings() throws IOException {
        return sendBytes(new byte[]{(byte)0x45}).data;
    }


    public enum MifareResultType {
        SUCCESS,
        MORE_DATA,
        EOF
    }

    public class MifareResult {
        public byte[] data;
        public MifareResultType resultType;
    }

    public MifareResult sendBytes(byte[] cmd) throws IOException {
        byte[] response = cardCommunicator.transceive(cmd);

        MifareResult result = new MifareResult();
        result.data = ByteArray.appendCut(null, response);

        switch (response[0]) {
            case (byte)0xAF:
                result.resultType = MifareResultType.MORE_DATA;
                break;

            case (byte)0xBE:
                result.resultType = MifareResultType.EOF;
                break;

            case (byte)0x00:
                result.resultType = MifareResultType.SUCCESS;
                break;

            default:
                throw new IOException("Error in card response: " + ByteArray.byteArrayToHexString(response));
        }

        return result;
    }

    public Challenge cardChallengeToCouplerChallenge(byte[] rndB, byte[] key)
            throws GeneralSecurityException {

        Cipher decipher = this.getCipher(key);

        if (rndB == null || rndB.length < 9) {
            throw new IllegalArgumentException("Not a valid challenge (application not existing?)");
        }

        rndB = ByteArray.appendCut(null, rndB);

        // We decrypt the challenge, and rotate one byte to the left
        rndB = decipher.doFinal(rndB);
        rndB = ByteArray.shiftLT(rndB);

        // Then we generate a random number as our challenge for the coupler
        byte[] plainCouplerChallenge = new byte[8];
        randomGenerator.nextBytes(plainCouplerChallenge);

        byte[] rndA = decipher.doFinal(plainCouplerChallenge);
        // XOR of rndA, rndB
        rndB = ByteArray.xor(rndA, rndB);
        // The result is encrypted again
        rndB = decipher.doFinal(rndB);

        // And sent back to the card
        byte[] challengeMessage = ByteArray.from((byte)0xAF).append(rndA).append(rndB).toArray();

        return new Challenge(challengeMessage, plainCouplerChallenge);
    }

    public boolean verifyCardResponse(byte[] cardResponse, byte[] originalPlainChallenge, byte[] key)
            throws GeneralSecurityException {
        Cipher decipher = this.getCipher(key);

        if (cardResponse == null)
            return false;

        if (cardResponse.length == 9)
            cardResponse = ByteArray.appendCut(null, cardResponse);

        if (cardResponse.length == 8) {
            // We decrypt the response and shift the rightmost byte "all around" (to the left)
            cardResponse = ByteArray.shiftRT(decipher.doFinal(cardResponse));
            if (Arrays.equals(cardResponse, originalPlainChallenge)) {
                return true;
            }
        }
        return false;
    }

    public byte[] getCardChallenge(byte keyNumber) throws Exception {
        // Issue command 0x0A with the key number we want to use
        byte[] cmd = ByteArray.from((byte)0x0A).append(keyNumber).toArray();
        // Send the command to the key, receive the challenge
        byte[] response = null;
        for (int i = 0; i < 3; i++) {
            try {
                response = cardCommunicator.transceive(cmd);
                break;
            } catch (Exception e) {
                if (i == 2)
                    throw e;
            }
        }

        return response;
    }

    public boolean authenticate(byte keyNumber, byte[] key) throws Exception {

        byte[] rndB = getCardChallenge(keyNumber);

        Challenge challenge = cardChallengeToCouplerChallenge(rndB, key);

        byte[] challengeMessage = challenge.getChallenge();
        byte[] plainCouplerChallenge = challenge.getChallengeResponse();

        byte[] cardResponse = null;
        for (int i = 0; i < 3; i++) {
            try {
                cardResponse = cardCommunicator.transceive(challengeMessage);
                // on success, do not try again
                break;
            } catch (Exception e) {
                if (i == 2)
                    throw e;
            }
        }

        return verifyCardResponse(cardResponse, plainCouplerChallenge, key);
    }

    /**
     * Opens communication to the card
     *
     * @throws IOException
     */
    public boolean connect() throws IOException {
        cardCommunicator.connect();
        return cardCommunicator.isConnected();
    }

    public void close() throws IOException {
        cardCommunicator.close();
    }
}
