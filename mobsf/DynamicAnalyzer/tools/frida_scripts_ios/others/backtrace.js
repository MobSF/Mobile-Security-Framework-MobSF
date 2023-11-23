//Credit: github.com/iddoeldor/frida-snippets
var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
send("\n[-] ======== Backtrace Start  ========");
send(backtrace);
send("\n[-] ======== Backtrace End  ========");