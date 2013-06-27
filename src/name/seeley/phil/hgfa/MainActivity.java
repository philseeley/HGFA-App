package name.seeley.phil.hgfa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import android.os.Bundle;
import android.app.Activity;
import android.content.Intent;
import android.util.Base64;
import android.view.Menu;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

public class MainActivity extends Activity
{
  static final String EOL = "\n";

  static final String publicPEM = "MFUwEwYHKoZIzj0CAQYIKoZIzj0DAQQDPgAEZFvqdcZ+KiZIxH7/vOruEkK5IP3WwZtoiLL+chQjEzb5nSIjLKKATk2Utz/SpQmS0EvOGTKm/EPCmb6j";

  private PublicKey publicKey;

  static
  {
    Security.insertProviderAt(
        new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
  }

  @Override
  public void onCreate(Bundle savedInstanceState)
  {
    super.onCreate(savedInstanceState);

    try
    {
      KeyFactory fact = KeyFactory.getInstance("ECDSA");
      EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(
          publicPEM, Base64.DEFAULT));
      publicKey = fact.generatePublic(publicKeySpec);

    } catch (NoSuchAlgorithmException e)
    {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (InvalidKeySpecException e)
    {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    
    setContentView(R.layout.activity_main);
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
        
        try
        {
          String line;
          while ((line = reader.readLine()) != null)
          {
            String elements[] = line.split(":");
            String tag = elements[0];
            String value = elements[1];

            if ("_SIG".equals(tag))
            {
              Signature instance = Signature.getInstance("ECDSA");
              instance.initVerify(publicKey);
              instance.update(data.toString().getBytes());
              if (instance.verify(Base64.decode(value, Base64.DEFAULT)))
                imageView.setImageResource(R.drawable.valid);
              else
                imageView.setImageResource(R.drawable.invalid);
            } else
            {
              data.append(line);
              data.append(EOL);
              
              infoTextView.setText(data);
            }
          }
        } catch (IOException e)
        {
          // TODO Auto-generated catch block
          e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
          // TODO Auto-generated catch block
          e.printStackTrace();
        } catch (InvalidKeyException e)
        {
          // TODO Auto-generated catch block
          e.printStackTrace();
        } catch (SignatureException e)
        {
          // TODO Auto-generated catch block
          e.printStackTrace();
        }
      }
    }
  }
}
