package local.pureguard;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;

// Serves Pure Guard's own APK, read-only, to the app the user shares it with (Quick Share,
// Bluetooth...). Not exported: only a share with a granted URI can read it.
public final class ApkProvider extends ContentProvider {
    static final Uri URI = Uri.parse("content://local.pureguard.apk/PureGuard.apk");
    static final String TYPE = "application/vnd.android.package-archive";

    private File apk() {
        return new File(getContext().getApplicationInfo().sourceDir);
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        return ParcelFileDescriptor.open(apk(), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    // Name and size: share targets show them and some refuse a file without them.
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        MatrixCursor c = new MatrixCursor(new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
        c.addRow(new Object[]{"PureGuard.apk", apk().length()});
        return c;
    }

    @Override public String getType(Uri uri) { return TYPE; }
    @Override public boolean onCreate() { return true; }
    @Override public Uri insert(Uri uri, ContentValues v) { return null; }
    @Override public int delete(Uri uri, String s, String[] a) { return 0; }
    @Override public int update(Uri uri, ContentValues v, String s, String[] a) { return 0; }
}
