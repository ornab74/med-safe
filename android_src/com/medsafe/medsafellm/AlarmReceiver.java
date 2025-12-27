// android_src/com/medsafe/medsafellm/AlarmReceiver.java
package com.medsafe.medsafellm;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

public class AlarmReceiver extends BroadcastReceiver {
    private static final String CHANNEL_ID = "medicine_reminders";

    @Override
    public void onReceive(Context context, Intent intent) {
        String title = intent.getStringExtra("title");
        String body  = intent.getStringExtra("body");
        if (title == null) title = "Medicine Reminder";
        if (body == null) body = "Time to take your medicine";

        NotificationManager nm =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

        // Android 8+ channel
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Medicine Reminders",
                    NotificationManager.IMPORTANCE_HIGH
            );
            channel.setDescription("Scheduled medicine reminders");
            if (nm != null) nm.createNotificationChannel(channel);
        }

        Notification.Builder builder =
                (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                        ? new Notification.Builder(context, CHANNEL_ID)
                        : new Notification.Builder(context);

        builder.setContentTitle(title)
               .setContentText(body)
               .setSmallIcon(context.getApplicationInfo().icon)
               .setAutoCancel(true)
               .setPriority(Notification.PRIORITY_HIGH);

        int nid = (int) (System.currentTimeMillis() & 0x7fffffff);
        if (nm != null) nm.notify(nid, builder.build());
    }
}
