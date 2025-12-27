// android_src/com/medsafe/medsafellm/BootReceiver.java
package com.medsafe.medsafellm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // Option: launch app so Python can resync alarms from encrypted DB.
        // If you don't want the app UI to pop open on boot, replace this with
        // a WorkManager job or schedule a "resync" alarm instead.
        Intent launch = context.getPackageManager()
                .getLaunchIntentForPackage(context.getPackageName());

        if (launch != null) {
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(launch);
        }
    }
}
