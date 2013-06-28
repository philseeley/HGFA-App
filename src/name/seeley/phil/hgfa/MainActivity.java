package name.seeley.phil.hgfa;

import java.io.BufferedReader;
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

import android.os.Bundle;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.SimpleAdapter;

@SuppressLint("SimpleDateFormat")
public class MainActivity extends Activity
{
  private static final String EOL = "\n";

  private static final String publicPEM = "MFUwEwYHKoZIzj0CAQYIKoZIzj0DAQQDPgAEZFvqdcZ+KiZIxH7/vOruEkK5IP3WwZtoiLL+chQjEzb5nSIjLKKATk2Utz/SpQmS0EvOGTKm/EPCmb6j";

  private String T = "HGFA";
      
  private PublicKey publicKey;
  private static SimpleDateFormat dateFormatter;
  private static Date now = new Date();

  static
  {
    Security.insertProviderAt(
        new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

    dateFormatter = new SimpleDateFormat("yyyy-MM-dd");
  }

  @Override
  public void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);

    setContentView(R.layout.activity_main);

    try
    {
      KeyFactory fact = KeyFactory.getInstance("ECDSA");
      EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(
          publicPEM, Base64.DEFAULT));
      publicKey = fact.generatePublic(publicKeySpec);

    } catch (GeneralSecurityException e)
    {
      Log.e(T, e.toString());
    }
  }

  @Override
  public boolean onCreateOptionsMenu(Menu menu)
  {
    getMenuInflater().inflate(R.menu.activity_main, menu);
    return true;
  }

  public void scan(View view)
  {
    Intent intent = new Intent("com.google.zxing.client.android.SCAN");
    intent.putExtra("com.google.zxing.client.android.SCAN.SCAN_MODE",
        "QR_CODE_MODE");
    startActivityForResult(intent, 0);
  }

  public void onActivityResult(int requestCode, int resultCode, Intent intent)
  {
    if (requestCode == 0)
    {
      if (resultCode == RESULT_OK)
      {
        String contents = intent.getStringExtra("SCAN_RESULT");

        BufferedReader reader = new BufferedReader(new StringReader(contents));

        StringBuffer data = new StringBuffer();
        
        String from[] = {"tag", "value", "icon"};
        int to[] = {R.id.tag, R.id.value, R.id.icon};
        
        List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();
        
        SimpleAdapter adapter = new SimpleAdapter(this, items, R.layout.list_view, from, to);

        ListView infoListView = (ListView) findViewById(R.id.listView);
        ImageView imageView = (ImageView) findViewById(R.id.imageView);

        infoListView.setAdapter(adapter);
        imageView.setImageResource(R.drawable.blank);

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
                map.put("value", value);
                map.put("icon", iconID);

                items.add(map);
              }
            }
          }

          imageView.setImageResource(resultID);

        } catch (Exception e)
        {
          Log.e(T, e.toString());
        }
      }
    }
  }
}
