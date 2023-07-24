Java.perform(function() {
    try {
        var OkHttpClient;
        try {
            OkHttpClient = Java.use('okhttp3.OkHttpClient');
        } catch (error) {
            console.error("Error: Network Traffic not found.");
            return;
        }
        var RequestBody = Java.use('okhttp3.RequestBody');
        var Buffer = Java.use('okio.Buffer');
        var ByteString = Java.use('okio.ByteString');
        var MediaType = Java.use('okhttp3.MediaType');
        var ResponseBody = Java.use('okhttp3.ResponseBody');
        var Response = Java.use('okhttp3.Response');
        var Base64 = Java.use('android.util.Base64'); // Import Base64
        var GZIPInputStream = Java.use('java.util.zip.GZIPInputStream');
        var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
        var InputStream = Java.use('java.io.InputStream');
        var InputStreamReader = Java.use('java.io.InputStreamReader');
        var BufferedReader = Java.use('java.io.BufferedReader');

        OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
            send("URL: " + request.url().toString());
            send("Method: " + request.method());

            var headers = request.headers();
            for(var i = 0; i < headers.size(); i++) {
                send(headers.name(i) + ": " + headers.value(i));
            }

            var body = request.body();
            if(body !== null) {
                var buffer = Buffer.$new();
                body.writeTo(buffer);
                var bodyBytes = buffer.readByteArray();
                var strBody = Base64.encodeToString(bodyBytes, 0); // use Base64 encoding
                send("Encoded Request body: " + strBody);
                // Decode and ungzip the body
                var decodedBytes = Base64.decode(strBody, 0);
                var byteArrayInputStream = Java.use('java.io.ByteArrayInputStream').$new(decodedBytes);
                var gzipInputStream = GZIPInputStream.$new(byteArrayInputStream);
                var bufferedReader = BufferedReader.$new(InputStreamReader.$new(gzipInputStream, "UTF-8"));
                var stringBuilder = Java.use('java.lang.StringBuilder').$new();
                var line;
                while ((line = bufferedReader.readLine()) !== null) {
                    stringBuilder.append(line);
                }
                bufferedReader.close();
                gzipInputStream.close();
                send("Decoded Request body: " + stringBuilder.toString());
            }

            var call = this.newCall(request);
            call.execute.implementation = function() {
                var response = this.execute();
                if(response.body() !== null) {
                    var responseBodyString = response.body().string();
                    send("Response body: " + responseBodyString);

                    var mediaType = response.body().contentType();
                    var responseBody = ResponseBody.create(mediaType, responseBodyString);
                    response = Response.newBuilder().body(responseBody).build();
                }
                return response;
            };
            return call;
        };
    } catch(error) {
        console.error("Error: " + error);
    }
});
