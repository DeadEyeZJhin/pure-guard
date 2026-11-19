package local.pureguard;

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;

// Boot / update / shutdown hook. (A DeviceAdminReceiver because older builds were device admins;
// Guard.heal releases that admin.)
public final class Admin extends DeviceAdminReceiver {
    @Override
    public void onReceive(Context c, Intent i) {
        super.onReceive(c, i);
        String a = i.getAction();
        if (Intent.ACTION_BOOT_COMPLETED.equals(a) || Intent.ACTION_MY_PACKAGE_REPLACED.equals(a)) Guard.apply(c);
        // Next boot starts on CleanBrowsing Private DNS until the VPN is up (no unfiltered seconds).
        if (Intent.ACTION_SHUTDOWN.equals(a)) Guard.vpnDown(c);
    }
}
