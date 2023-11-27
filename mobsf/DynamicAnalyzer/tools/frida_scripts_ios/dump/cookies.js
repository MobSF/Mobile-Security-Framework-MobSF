function dumpCookies(){
  send('Dumping Cookies');
  var cookieArr = [];
  var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
  for (var i = 0, l = cookies.count(); i < l; i++) {
      var cookie = cookies['- objectAtIndex:'](i);
      var expiry = cookie.expiresDate() ? cookie.expiresDate().toString() : 'null';
      cookieArr.push({
        name: cookie.Name().toString(),
        value: cookie.Value().toString(),
        domain: cookie.domain().toString(),
        path: cookie.path().toString(),
        expiry: expiry,
        httponly: cookie.isHTTPOnly().toString(),
        secure: cookie.isSecure().toString(),
        version: cookie.version().toString(),
      });
      send(JSON.stringify({'[MBSFDUMP] cookies': cookieArr}));
  }
}
try {
  dumpCookies();
} catch(err) {}