package com.secretariat.workflow;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Bundle;
import android.provider.MediaStore;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;
import java.io.File;
import java.io.IOException;

public class MainActivity extends Activity {
    private WebView webView;
    private static final String APP_URL = "https://kp-tracking-app.streamlit.app";
    private ValueCallback<Uri[]> mUploadMessage;
    private static final int FILECHOOSER_RESULTCODE = 1;
    private static final int CAMERA_RESULTCODE = 2;
    private Uri mCameraImageUri;
    private long backPressedTime;
    private Toast backToast;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);
        setContentView(R.layout.splash_screen);
        
        new android.os.Handler().postDelayed(() -> { loadMainApp(); }, 2000);
    }
    
    private void loadMainApp() {
        setContentView(R.layout.activity_main);
        webView = findViewById(R.id.webView);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setMediaPlaybackRequiresUserGesture(false);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);
        settings.setGeolocationEnabled(true);
        settings.setSupportZoom(true);
        settings.setBuiltInZoomControls(true);
        settings.setDisplayZoomControls(false);
        settings.setUseWideViewPort(true);
        settings.setLoadWithOverviewMode(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                if (!isNetworkAvailable()) { showNoInternetScreen(); }
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, FileChooserParams fileChooserParams) {
                if (mUploadMessage != null) { mUploadMessage.onReceiveValue(null); }
                mUploadMessage = filePathCallback;
                showFileUploadDialog();
                return true;
            }
        });

        if (isNetworkAvailable()) { webView.loadUrl(APP_URL); } 
        else { showNoInternetScreen(); }
    }
    
    private void showFileUploadDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Select Upload Method");
        String[] options = {"Take Photo", "Choose from Gallery", "Browse Files"};
        builder.setItems(options, (dialog, which) -> {
            if (which == 0) openCamera();
            else if (which == 1) openGallery();
            else openFilePicker();
        });
        builder.setOnCancelListener(dialog -> {
            if (mUploadMessage != null) { mUploadMessage.onReceiveValue(null); mUploadMessage = null; }
        });
        builder.show();
    }
    
    private void openCamera() {
        Intent cameraIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        if (cameraIntent.resolveActivity(getPackageManager()) != null) {
            try {
                String timeStamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(new java.util.Date());
                File photoFile = File.createTempFile("JPEG_" + timeStamp + "_", ".jpg", getExternalFilesDir(null));
                mCameraImageUri = Uri.fromFile(photoFile);
                cameraIntent.putExtra(MediaStore.EXTRA_OUTPUT, mCameraImageUri);
                startActivityForResult(cameraIntent, CAMERA_RESULTCODE);
            } catch (IOException ex) {
                Toast.makeText(this, "Error creating file", Toast.LENGTH_SHORT).show();
            }
        }
    }
    
    private void openGallery() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("image/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(Intent.createChooser(intent, "Select Image"), FILECHOOSER_RESULTCODE);
    }
    
    private void openFilePicker() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(Intent.createChooser(intent, "Select File"), FILECHOOSER_RESULTCODE);
    }
    
    private void showNoInternetScreen() {
        webView.loadData("<html><body style='text-align:center; padding:50px; font-family:sans-serif; background:#f0f4f8;'><h2 style='color:#15346b;'>No Internet Connection</h2><p style='color:#475569;'>Please check your network settings and try again.</p><button onclick='location.reload()' style='padding:12px 30px; background:#15346b; color:white; border:none; border-radius:25px; margin-top:20px; font-size:16px; cursor:pointer;'>Retry</button></body></html>", "text/html", "UTF-8");
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
        super.onActivityResult(requestCode, resultCode, intent);
        if (requestCode == FILECHOOSER_RESULTCODE || requestCode == CAMERA_RESULTCODE) {
            if (null == mUploadMessage) return;
            Uri result = null;
            if (resultCode == RESULT_OK) {
                if (requestCode == CAMERA_RESULTCODE) { result = mCameraImageUri; } 
                else if (intent != null) { result = intent.getData(); }
            }
            mUploadMessage.onReceiveValue(result != null ? new Uri[]{result} : null);
            mUploadMessage = null;
        }
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) { webView.goBack(); } 
        else {
            if (backPressedTime + 2000 > System.currentTimeMillis()) {
                if (backToast != null) backToast.cancel();
                super.onBackPressed();
            } else {
                backToast = Toast.makeText(getBaseContext(), "Press back again to exit", Toast.LENGTH_SHORT);
                backToast.show();
                backPressedTime = System.currentTimeMillis();
            }
        }
    }

    private boolean isNetworkAvailable() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
        return activeNetwork != null && activeNetwork.isConnected();
    }
}