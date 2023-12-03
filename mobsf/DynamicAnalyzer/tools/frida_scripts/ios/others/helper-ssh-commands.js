// From: https://github.com/iddoeldor/frida-snippets#log-ssh-commands
var NMSSHChannel = ObjC.classes.NMSSHChannel;
if (!NMSSHChannel){
    send('Class NMSSHChannel not found')
    return;
}
Interceptor.attach(NMSSHChannel['- execute:error:timeout:'].implementation, {  
    onEnter: function(args) {  
    this.cmd = ObjC.Object(args[2]).toString();
    this.timeout = args[4];
    }, 
    onLeave: function(retv) {  
    send('CMD: ' + ObjC.Object(args[2]).toString() + 'Timeout: ' + args[4] + 'Ret: ' + retv);
    }  
}); 