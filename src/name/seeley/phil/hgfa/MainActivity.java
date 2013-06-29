package name.seeley.phil.hgfa;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

import android.net.Uri;
import android.os.Bundle;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.SimpleAdapter;
import android.widget.TextView;

@SuppressLint("SimpleDateFormat")
public class MainActivity extends Activity
{
  private static final String EOL = "\n";

  private static final String PUBLIC_PEM = "MFUwEwYHKoZIzj0CAQYIKoZIzj0DAQQDPgAEZFvqdcZ+KiZIxH7/vOruEkK5IP3WwZtoiLL+chQjEzb5nSIjLKKATk2Utz/SpQmS0EvOGTKm/EPCmb6j";

  private static final String T = "HGFA";
  private static final int SCAN_IMAGE_REQ = 10;
  private static final int SELECT_IMAGE_REQ = 20;

  private static PublicKey publicKey;
  private static SimpleDateFormat dateFormatter;
  private static Date now = new Date();

  static
  {
    Security.insertProviderAt(
        new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

    dateFormatter = new SimpleDateFormat("yyyy-MM-dd");

    try
    {
      KeyFactory fact = KeyFactory.getInstance("ECDSA");
      EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(
          PUBLIC_PEM, Base64.DEFAULT));
      publicKey = fact.generatePublic(publicKeySpec);

    }
    catch (GeneralSecurityException e)
    {
      Log.e(T, e.toString());
    }
  }

  @Override
  public void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);

    setContentView(R.layout.activity_main);
  }

  @Override
  public boolean onCreateOptionsMenu(Menu menu)
  {
    getMenuInflater().inflate(R.menu.activity_main, menu);
    return true;
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item)
  {
    // Handle item selection
    switch (item.getItemId())
    {
    case R.id.menu_scan_image:
      startImageSelect();
      return true;
    default:
      return super.onOptionsItemSelected(item);
    }
  }

  public void startScan(View view)
  {
    Intent intent = new Intent("com.google.zxing.client.android.SCAN");
    intent.putExtra("com.google.zxing.client.android.SCAN.SCAN_MODE",
        "QR_CODE_MODE");
    startActivityForResult(intent, SCAN_IMAGE_REQ);
  }

  public void startImageSelect()
  {
    Intent photoPickerIntent = new Intent(Intent.ACTION_PICK);
    photoPickerIntent.setType("image/*");
    startActivityForResult(photoPickerIntent, SELECT_IMAGE_REQ);
  }

  public void onActivityResult(int requestCode, int resultCode, Intent intent)
  {
    if (resultCode == RESULT_OK)
    {
      TextView infoTextView = (TextView) findViewById(R.id.text_info);
      infoTextView.setText(null);

      String contents = null;

      switch (requestCode)
      {
      case SCAN_IMAGE_REQ:
        contents = intent.getStringExtra("SCAN_RESULT");
        break;
      case SELECT_IMAGE_REQ:
        try
        {
          Uri selectedImage = intent.getData();

          InputStream imageStream = getContentResolver().openInputStream(
              selectedImage);
          Bitmap bitmap = BitmapFactory.decodeStream(imageStream);
          int width = bitmap.getWidth(), height = bitmap.getHeight();
          int[] pixels = new int[width * height];
          bitmap.getPixels(pixels, 0, width, 0, 0, width, height);

          try
          {
            RGBLuminanceSource source = new RGBLuminanceSource(width, height,
                pixels);
            BinaryBitmap binaryBitmap = new BinaryBitmap(new HybridBinarizer(
                source));
            QRCodeReader qrReader = new QRCodeReader();
            Result result = qrReader.decode(binaryBitmap);
            contents = result.getText();
          }
          catch (NotFoundException e)
          {
            infoTextView.setText("No data found");
          }

          processContents(contents);

        }
        catch (Exception e)
        {
          infoTextView.setText(e.getMessage());
        }
        break;
      }

      processContents(contents);
    }
  }

  private void processContents(String contents)
  {
    String from[] = { "tag", "icon", "value" };
    int to[] = { R.id.tag, R.id.icon, R.id.value };

    List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();

    SimpleAdapter adapter = new SimpleAdapter(this, items, R.layout.list_view,
        from, to);

    ListView infoListView = (ListView) findViewById(R.id.list_info);
    ImageView resultImageView = (ImageView) findViewById(R.id.image_result);
    TextView infoTextView = (TextView) findViewById(R.id.text_info);

    infoListView.setAdapter(adapter);
    resultImageView.setImageResource(R.drawable.blank);

    if (contents != null)
    {
      BufferedReader reader = new BufferedReader(new StringReader(contents));

      StringBuffer data = new StringBuffer();

      try
      {
        int resultID = R.drawable.unknown;
        boolean expired = false;

        String line;
        while ((line = reader.readLine()) != null)
        {
          String elements[] = line.split(":");

          if (elements.length < 2)
          {
            data.append(line);
            data.append(EOL);
          }
          else
          {
            String tag = elements[0];
            String value = elements[1];
            int iconID = R.drawable.blank_small;

            if ("_SIG".equals(tag))
            {
              Signature instance = Signature.getInstance("ECDSA");
              instance.initVerify(publicKey);
              instance.update(data.toString().getBytes());
              if (instance.verify(Base64.decode(value, Base64.DEFAULT)))
              {
                if (expired)
                  resultID = R.drawable.expired;
                else
                  resultID = R.drawable.valid;
              }
              else
                resultID = R.drawable.invalid;
            }
            else
            {
              data.append(line);
              data.append(EOL);

              if (tag.matches("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
              {
                // We check date tags for expiry, but reorder for layout.

                String tmp = tag;
                tag = value;
                value = tmp;
                Date expires = dateFormatter.parse(value);

                if (expires.before(now))
                {
                  iconID = R.drawable.expired_small;
                  if ("Expiry".equals(tag))
                    expired = true;
                }
              }

              Map<String, Object> map = new HashMap<String, Object>();

              map.put("tag", tag);
              map.put("icon", iconID);
              map.put("value", value);

              items.add(map);
            }
          }
        }

        resultImageView.setImageResource(resultID);

      }
      catch (Exception e)
      {
        infoTextView.setText(e.getMessage());
      }
    }
  }
}
