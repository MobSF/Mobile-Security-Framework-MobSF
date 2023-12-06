/* 
    Description: Android OKHTTP HTTP/HTTPS requests and responses logger
    Credit: M4v3r1ck and nneonneo
    This script will add HttpLoggingInterceptor at OkHttpClient, so the HttpLoggingInterceptor will print all requests and responses.
    This strategy does not matter if you are doing TLS Pinning bypass 
    Link:
        https://github.com/square/okhttp/tree/master/okhttp-logging-interceptor
*/

setTimeout(function() 
{
    Java.perform(() => 
    {

        //Create a new instance of HttpLoggingInterceptor class
        function getInterceptor() 
        {
            try 
            {
                const HttpLoggingInterceptor = Java.use('okhttp3.logging.HttpLoggingInterceptor');
                const Level = Java.use('okhttp3.logging.HttpLoggingInterceptor$Level');

                const MyLogger = Java.registerClass(
                {
                    name: 'MyLogger',
                    superClass: Java.use('java.lang.Object'),
                    implements: [Java.use('okhttp3.logging.HttpLoggingInterceptor$Logger')],
                    methods: 
                    {
                        log: [
                        {
                            returnType: 'void',
                            argumentTypes: ['java.lang.String'],
                            implementation: function(message) 
                            {
                                send('    [LOG] ' + message);
                            }
                        }]
                    },
                });

                var logInstance = HttpLoggingInterceptor.$new(MyLogger.$new());

                //If you want to log at the logcat just change to the line bellow
                //var logInstance = HttpLoggingInterceptor.$new();
                logInstance.setLevel(Level.BODY.value);

                return logInstance;

            } 
            catch (err) 
            {
                send("[-] Error creating interceptor")
                send(err);
                send(err.stack)
                return null;
            }
        }

        try 
        {
            var Builder = Java.use('okhttp3.OkHttpClient$Builder')
            var build = Builder.build.overload();

            build.implementation = function() 
            {
                send('[+] OkHttpClient$Builder ==> Adding log interceptor')

                //Add the new interceptor before call the 'build' function
                try 
                {
                    this.addInterceptor(getInterceptor());
                } 
                catch (err) 
                {
                    send('[-] OkHttpClient$Builder.addInterceptor error');
                }

                return build.call(this);
            }
        } 
        catch (err) 
        {
            send('[-] OkHttpClient$Builder error');
            send(err);
        }
    });
}, 1000);


Java.perform(function() 
{
    function okhttp3RealCall(){
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var RealCall = Java.use("okhttp3.RealCall");
        var Buffer = Java.use("okio.Buffer");
        var StandardCharsets = Java.use("java.nio.charset.StandardCharsets");

        RealCall.getResponseWithInterceptorChain.implementation = function() 
        {
            var response = this.getResponseWithInterceptorChain()
            var request = response.request()
            send("REQUEST: " + request)
            send(request.headers())
            var body = "";

            if (request.headers().get("content-type") === "application/x-www-form-urlencoded") 
            {
                var buffer = Buffer.$new()
                request.body().writeTo(buffer)
                body = buffer.readString(StandardCharsets.UTF_8.value)
            }
            
            send(body)
            send("RESPONSE: " + response)
            send(response.headers())
            return response
        }
    }
    try{
        okhttp3RealCall();
    } catch(err){}
});