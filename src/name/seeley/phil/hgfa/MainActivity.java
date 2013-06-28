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
import java.util.Date;

import android.os.Bundle;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

@SuppressLint("SimpleDateFormat")
public class MainActivity extends Activity
{
  private static final String EOL = "\n";

  private static final String publicPEM = "MFUwEwYHKoZIzj0CAQYIKoZIzj0DAQQDPgAEZFvqdcZ+KiZIxH7/vOruEkK5IP3WwZtoiLL+chQjEzb5nSIjLKKATk2Utz/SpQmS0EvOGTKm/EPCmb6j";

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
      TextView infoTextView = (TextView) findViewById(R.id.text_info);

      infoTextView.setText(e.toString());
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

        TextView infoTextView = (TextView) findViewById(R.id.text_info);
        ImageView imageView = (ImageView) findViewById(R.id.imageView);

        infoTextView.setText("");
        imageView.setImageResource(R.drawable.blank);

        try
        {
          int resultID = R.drawable.unknown;
          boolean expired = true;

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

                if ("Expires".equals(tag))
                {
                  Date expires = dateFormatter.parse(value);

                  Log.d("t", expires.toString());
                  if (expires.after(now))
                    expired = false;
                }
                else if (tag.matches("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
                {
                  Log.d("t", line);
                }
              }
            }
          }

          infoTextView.setText(data);
          imageView.setImageResource(resultID);

        } catch (Exception e)
        {
          infoTextView.setText(e.toString());
        }
      }
    }
  }
}
