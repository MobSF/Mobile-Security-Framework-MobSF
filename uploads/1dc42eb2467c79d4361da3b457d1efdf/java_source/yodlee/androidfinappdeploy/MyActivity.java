package yodlee.androidfinappdeploy;

import android.app.Activity;
import android.app.Fragment;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.MenuItem.OnMenuItemClickListener;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebSettings;
import android.webkit.WebView;

public class MyActivity
  extends Activity
{
  public MyActivity() {}
  
  protected void onCreate(Bundle paramBundle)
  {
    super.onCreate(paramBundle);
    setContentView(2130903040);
    paramBundle = (WebView)findViewById(2131230721);
    paramBundle.loadUrl("file:///android_asset/www/index.html");
    if (Build.VERSION.SDK_INT >= 19) {
      WebView.setWebContentsDebuggingEnabled(true);
    }
    paramBundle.getSettings().setJavaScriptEnabled(true);
  }
  
  public boolean onCreateOptionsMenu(Menu paramMenu)
  {
    getMenuInflater().inflate(2131165184, paramMenu);
    paramMenu.findItem(2131230722).setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener()
    {
      public boolean onMenuItemClick(MenuItem paramAnonymousMenuItem)
      {
        ((WebView)findViewById(2131230721)).reload();
        return true;
      }
    });
    return true;
  }
  
  public boolean onOptionsItemSelected(MenuItem paramMenuItem)
  {
    if (paramMenuItem.getItemId() == 2131230723) {
      return true;
    }
    return super.onOptionsItemSelected(paramMenuItem);
  }
  
  public static class PlaceholderFragment
    extends Fragment
  {
    public PlaceholderFragment() {}
    
    public View onCreateView(LayoutInflater paramLayoutInflater, ViewGroup paramViewGroup, Bundle paramBundle)
    {
      return paramLayoutInflater.inflate(2130903041, paramViewGroup, false);
    }
  }
}
