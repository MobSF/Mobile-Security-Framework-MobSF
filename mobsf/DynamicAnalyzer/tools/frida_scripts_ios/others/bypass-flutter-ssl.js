/* Description: Flutter bypass ssl pinning
 * Mode: S
 * Version: 1.0
 * Credit: https://bhattsameer.github.io/2021/06/23/Intercepting-flutter-iOS-application.html
 * Author: @noobpk
 */
var colors = {
    "resetColor": "\x1b[0m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "red": "\x1b[31m"
}

function hook_ssl_verify_result(address)
{
    Interceptor.attach(address, {
    onEnter: function(args) {
        send("Disabling SSL validation")
    },
    onLeave: function(retval)
    {
      retval.replace(0x1);
    }
    });
 }
function disablePinning()
{
   var pattern = "FF 03 05 D1 FC 6F 0F A9 F8 5F 10 A9 F6 57 11 A9 F4 4F 12 A9 FD 7B 13 A9 FD C3 04 91 08 0A 80 52"
   Process.enumerateRangesSync('r-x').filter(function (m)
   {
      if (m.file) return m.file.path.indexOf('Flutter') > -1;
      return false;
   }).forEach(function (r)
   {
      Memory.scanSync(r.base, r.size, pattern).forEach(function (match) {
      send('[+] ssl_verify_result found at: ' + match.address.toString());
      hook_ssl_verify_result(match.address);
      send('[*] Started: Bypass Flutter SSL-Pinning');

     });
   });
 }
setTimeout(disablePinning, 1000)
