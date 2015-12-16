package org.dematte.nfc.nfcremoteexample;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Log;
import org.dematte.nfc.android.AndroidCommunicator;
import org.dematte.nfc.common.MifareDesfire;

import java.lang.reflect.Method;
import java.util.Arrays;


/**
 * An example activity that works around Android < 5 test presence bug
 *
 * For the solution to work, you basically need three pieces:
 * 1) a Thread class. This rearms the internal Android watchdog, so it does not perform
 *    a "select" any time there is no communication within 125 ms
 *
 * 2) some stubs to call internal methods through reflection
 *
 * 3) an override to onNewIntent which will start the Thread class.
 *    You will have this override anyway, to use NFC, but you will need to perform a
 *    couple of steps here.
 */
public class MainActivity extends Activity {

    // Data and objects needed for foreground dispatching of Nfc intents
    protected PendingIntent pendingIntent;
    protected IntentFilter[] intentFiltersArray;
    protected String[][] techListsArray;
    protected NfcAdapter nfcAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Initialize additional data for foreground dispatching of Nfc intents
        this.pendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        this.intentFiltersArray = new IntentFilter[]{ new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED) };
        this.techListsArray = new String[][] {
                new String[] { android.nfc.tech.IsoDep.class.getName() },
                new String[] { android.nfc.tech.MifareClassic.class.getName() },
                new String[] { android.nfc.tech.NfcV.class.getName() }
        };

        this.nfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    @Override
    public void onPause() {
        super.onPause();
        nfcAdapter.disableForegroundDispatch(this);
    }

    @Override
    public void onResume() {
        super.onResume();
        nfcAdapter.enableForegroundDispatch(this, pendingIntent, intentFiltersArray, techListsArray);
    }

    // 1) the "rearm" thread
    static class CardWatchdogRearm extends Thread {

        private final Object nfcTag;
        private final int nativeHandle;

        CardWatchdogRearm(Object nfcTag, int nativeHandle) {
            this.nfcTag = nfcTag;
            this.nativeHandle = nativeHandle;
        }

        @Override
        public void run() {
            // After 10 seconds, die anyway
            for (int i = 0; i < 250; ++i) {
                try {
                    int result = INfcTag_connect(nfcTag, nativeHandle, 0);
                    boolean present = INfcTag_isPresent(nfcTag, nativeHandle);
                    if (!present) {
                        Log.d("CardWatchdogRearm", "INfcTag_connect: " + result);
                        break;
                    }

                    Thread.sleep(40);
                }
                catch (Exception e) {
                    Log.e("CardWatchdogRearm", e.getMessage());
                    break;
                }
            }
        }
    }



    public static Object Tag_getTagService(Tag that) {
        try {
            Class c = Tag.class;
            //c = Class.forName("android.nfc.Tag");
            Method m = c.getMethod("getTagService");
            Object nfcTag = m.invoke(that);
            return nfcTag;
        }
        catch (Exception ex) {
            Log.e("NfcRemoteExample", ex.getMessage());
            return null;
        }
    }

    public static int Tag_getServiceHandle(Tag that) {
        try {
            Class c = Tag.class;
            //c = Class.forName("android.nfc.Tag");
            Method m = c.getMethod("getServiceHandle");
            int serviceHandle = (Integer)m.invoke(that);
            return serviceHandle;
        }
        catch (Exception ex) {
            Log.e("NfcRemoteExample", ex.getMessage());
            return 0;
        }
    }

    public static int INfcTag_connect(Object that, int nativeHandle, int technology) {
        try {
            Class c = Class.forName("android.nfc.INfcTag$Stub$Proxy");

            Method m = c.getMethod("connect", int.class, int.class);
            return (Integer)m.invoke(that, nativeHandle, technology);
        }
        catch (Exception ex) {
            Log.e("NfcRemoteExample", ex.getMessage());
            return -1;
        }
    }

    //public boolean isPresent(int nativeHandle) throws RemoteException
    public static boolean INfcTag_isPresent(Object that, int nativeHandle) throws Exception {
        Class c = Class.forName("android.nfc.INfcTag$Stub$Proxy");

        Method m = c.getMethod("isPresent", int.class);
        boolean result = (Boolean)m.invoke(that, nativeHandle);
        return result;
    }

    @Override
    public void onNewIntent(Intent intent) {
        Tag currentTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (currentTag != null) {

            Object nfcTag = Tag_getTagService(currentTag);
            int nativeHandle = Tag_getServiceHandle(currentTag);

            new CardWatchdogRearm(nfcTag, nativeHandle).start();

            doSomethingWithThisCard(currentTag);
        }
    }


    private void doSomethingWithThisCard(Tag tag) {
        // You may want to use the basic IsoDep/Tag classes
        // final IsoDep communicator = IsoDep.get(tag);
        // communicator.transceive();
        // ...

        try {
            final AndroidCommunicator communicator = new AndroidCommunicator(IsoDep.get(tag), true);

            final MifareDesfire desfireCard = communicator.get(tag); // we do not specify a key here!
            if (desfireCard == null) {
                Log.d("NfcRemoteExample", "Not a desfire card");
            }
            else {
                byte[] zeroKey = new byte[8];
                Arrays.fill(zeroKey, (byte)0);

                boolean authenticated = desfireCard.authenticate((byte)0, zeroKey);

            }
        }
        catch (Exception e) {
            Log.e("NfcRemoteExample", e.getMessage(), e);
        }
    }
}